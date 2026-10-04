#![cfg(unix)]
#![allow(missing_docs, reason = "integration test symbols are executable fixtures")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "end-to-end test asserts on controlled local process and fixture state"
)]

use std::io::{BufRead as _, BufReader, Read as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use prost::Message as _;
use rusqlite::Connection;
use serde_json::Value;
use tempfile::TempDir;
use xtrace_domain::ContentHash;
use xtrace_protocol::generated::agent::RecordingEventKind;
use xtrace_protocol::xtf::{XtfEventEnvelope, XtfHeader};
use xtrace_store::verify_compressed_segment;

struct DaemonChild(Child);

impl std::ops::Deref for DaemonChild {
    type Target = Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for DaemonChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for DaemonChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn temp_root() -> TempDir {
    let base = std::env::temp_dir().canonicalize().expect("canonical temporary root");
    tempfile::Builder::new()
        .prefix("xtrace java synthetic ")
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
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

#[test]
fn java_client_authenticates_and_persists_verified_xtf_under_selected_root() {
    let root = temp_root();
    let repo = root.path().join("repository with spaces");
    let data_home = root.path().join("data home");
    std::fs::create_dir_all(&repo).expect("create repository");
    let initialized = run_cli(&["init", "--project-dir"], &repo, &data_home);
    assert!(
        initialized.status.success(),
        "init stderr: {}",
        String::from_utf8_lossy(&initialized.stderr)
    );

    let mut child = DaemonChild(
        Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["daemon", "--project-dir"])
            .arg(&repo)
            .env("XTRACE_DATA_HOME", &data_home)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn xtrace daemon"),
    );
    let stdout = child.stdout.take().expect("daemon stdout");
    let mut stderr = child.stderr.take().expect("daemon stderr");
    let stderr_reader = thread::spawn(move || drain_bounded(&mut stderr, 64 * 1024));
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line);
        let _ = send.send((reader, line, result));
    });
    let (mut daemon_stdout, line, read_result) =
        receive.recv_timeout(Duration::from_secs(10)).expect("daemon readiness within deadline");
    read_result.expect("read daemon readiness");
    let ready: Value = serde_json::from_str(&line).expect("readiness JSON");
    assert_eq!(ready["kind"], "daemon_bound");
    assert_eq!(ready["capture_supported"], false);
    assert_eq!(ready["ack_durability"], "staged");
    let bootstrap_path = PathBuf::from(ready["bootstrap_path"].as_str().expect("bootstrap path"));
    let session_dir = bootstrap_path.parent().expect("runtime session directory").to_path_buf();
    let bootstrap_bytes = std::fs::read(&bootstrap_path).expect("read daemon bootstrap");
    let mut tampered: Value = serde_json::from_slice(&bootstrap_bytes).expect("bootstrap JSON");
    let correct_pin = tampered["certificate_sha256_pin"].as_str().expect("pin").to_string();
    let wrong_pin = if correct_pin.starts_with('0') { "1" } else { "0" };
    tampered["certificate_sha256_pin"] = Value::String(wrong_pin.repeat(64));
    let bad_parent = root.path().join("private bad bootstrap parent");
    std::fs::create_dir(&bad_parent).expect("create private bootstrap parent");
    let bad_bootstrap = bad_parent.join("bootstrap with bad pin.json");
    std::fs::write(&bad_bootstrap, serde_json::to_vec(&tampered).expect("encode bootstrap"))
        .expect("write private test bootstrap");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&bad_parent, std::fs::Permissions::from_mode(0o700))
        .expect("secure test bootstrap parent permissions");
    std::fs::set_permissions(&bad_bootstrap, std::fs::Permissions::from_mode(0o600))
        .expect("secure test bootstrap permissions");

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let client = repo_root
        .join("adapters/java/build/install/xtrace-java-synthetic/bin/xtrace-java-synthetic");
    assert!(client.is_file(), "Gradle installDist must run before this test");
    let mut wrong_command = Command::new(&client);
    wrong_command.args(["--bootstrap"]).arg(&bad_bootstrap);
    let wrong_output = bounded_output(wrong_command, "wrong-pin Java client");
    assert!(!wrong_output.status.success());
    let wrong_error: Value = serde_json::from_slice(&wrong_output.stderr).expect("safe pin error");
    assert_eq!(wrong_error["code"], "XTR-JAVA-TLS-PIN");
    assert!(
        !String::from_utf8_lossy(&wrong_output.stderr)
            .contains(tampered["session_secret_base64"].as_str().expect("secret"))
    );
    let project_id = ready["project_id"].as_str().expect("project id");
    let project_root = data_home.join("projects").join(project_id);
    let preflight_connection = Connection::open(project_root.join("metadata.sqlite3"))
        .expect("selected project SQLite before valid client");
    let preflight_recordings: i64 = preflight_connection
        .query_row("SELECT COUNT(*) FROM recordings", [], |row| row.get(0))
        .expect("count recordings after rejected pin");
    assert_eq!(preflight_recordings, 0, "wrong pin sent no recording data");
    drop(preflight_connection);

    let mut client_command = Command::new(&client);
    client_command.args(["--bootstrap"]).arg(&bootstrap_path);
    let client_output = bounded_output(client_command, "synthetic Java XTP client");
    assert!(
        client_output.status.success(),
        "Java client failed safely: {}",
        String::from_utf8_lossy(&client_output.stderr)
    );
    assert!(
        client_output.stderr.is_empty(),
        "unexpected Java diagnostics: {}",
        String::from_utf8_lossy(&client_output.stderr)
    );
    let receipt: Value = serde_json::from_slice(&client_output.stdout).expect("Java receipt JSON");
    assert_eq!(receipt["kind"], "synthetic_recording_staged");
    assert_eq!(receipt["staged_acks"], 4);
    assert_eq!(receipt["capture_supported"], false);

    let connection =
        Connection::open(project_root.join("metadata.sqlite3")).expect("selected project SQLite");
    let recording_id = receipt["recording_id"].as_str().expect("recording id");
    let recording_bytes = uuid_bytes(recording_id);
    let (object_hash, event_count): (Vec<u8>, i64) = connection
        .query_row(
            "SELECT object_hash, event_count FROM recording_segments WHERE recording_id = ?1 AND segment_ordinal = 0",
            [&recording_bytes],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("recording segment committed to selected database");
    assert_eq!(event_count, 1);
    let hash_text = lower_hex(&object_hash);
    let object_path = project_root
        .join("objects/b3")
        .join(&hash_text[..2])
        .join(format!("{}.xtf.zst", &hash_text[2..]));
    let object = std::fs::read(object_path).expect("immutable XTF object");
    let content_hash = format!("b3:{hash_text}").parse::<ContentHash>().expect("content hash");
    let verified = verify_compressed_segment(&object, content_hash).expect("verify stored XTF");
    assert_eq!(verified.recording_id().to_string(), recording_id);
    assert_eq!(verified.project_id().to_string(), project_id);
    assert_eq!(verified.event_count(), 1);
    assert_eq!(verified.first_recording_seq(), 2);
    assert_eq!(verified.last_recording_seq(), 2);

    let logical = zstd::stream::decode_all(object.as_slice()).expect("decompress XTF");
    let header_len = u32::from_be_bytes(logical[8..12].try_into().expect("header length")) as usize;
    let header = XtfHeader::decode(&logical[12..12 + header_len]).expect("decode header");
    assert_eq!(header.event_count, 1);
    let event_pos = 12 + header_len;
    let event_len =
        u32::from_be_bytes(logical[event_pos..event_pos + 4].try_into().expect("event length"))
            as usize;
    let envelope = XtfEventEnvelope::decode(&logical[event_pos + 4..event_pos + 4 + event_len])
        .expect("decode event envelope");
    let event = envelope.event.expect("typed event");
    assert_eq!(event.event_id, receipt["event_id"].as_str().expect("event id"));
    assert_eq!(event.recording_seq, 2);
    assert_eq!(event.kind, RecordingEventKind::FrameEnter as i32);
    assert_eq!(event.symbol, "synthetic.handler");

    signal_and_wait(&mut child, "-INT");
    let mut trailing = String::new();
    assert_eq!(daemon_stdout.read_line(&mut trailing).expect("trailing daemon output"), 0);
    assert!(child.wait().expect("wait daemon").success());
    assert!(!bootstrap_path.exists(), "daemon removed one-shot bootstrap");
    assert!(!session_dir.exists(), "daemon removed runtime session directory");
    let _ = reader.join();
    let daemon_stderr = stderr_reader.join().expect("join daemon stderr reader");
    assert!(
        daemon_stderr.is_empty(),
        "unexpected daemon diagnostics: {}",
        String::from_utf8_lossy(&daemon_stderr)
    );
}

fn drain_bounded(reader: &mut impl std::io::Read, limit: usize) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let count = reader.read(&mut buffer).expect("drain daemon stderr");
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    kept
}

fn signal_and_wait(child: &mut Child, signal: &str) {
    let pid = child.id().to_string();
    assert!(Command::new("kill").args([signal, &pid]).status().expect("send signal").success());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().expect("poll daemon").is_some() {
            break;
        }
        assert!(Instant::now() < deadline, "daemon did not stop after {signal}");
        thread::sleep(Duration::from_millis(20));
    }
}

fn bounded_output(mut command: Command, label: &str) -> std::process::Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn bounded subprocess");
    let mut stdout = child.stdout.take().expect("captured stdout");
    let mut stderr = child.stderr.take().expect("captured stderr");
    let out = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).expect("read stdout");
        bytes
    });
    let err = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).expect("read stderr");
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll subprocess") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out.join();
            let _ = err.join();
            panic!("{label} exceeded its 30-second timeout");
        }
        thread::sleep(Duration::from_millis(10));
    };
    std::process::Output {
        status,
        stdout: out.join().expect("join stdout"),
        stderr: err.join().expect("join stderr"),
    }
}

fn uuid_bytes(value: &str) -> [u8; 16] {
    let digits: Vec<_> = value.bytes().filter(|byte| *byte != b'-').collect();
    assert_eq!(digits.len(), 32);
    let mut out = [0_u8; 16];
    for (index, pair) in digits.chunks_exact(2).enumerate() {
        out[index] = u8::from_str_radix(std::str::from_utf8(pair).expect("uuid ASCII"), 16)
            .expect("uuid hex");
    }
    out
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
