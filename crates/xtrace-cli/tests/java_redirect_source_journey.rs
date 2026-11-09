//! Real Spring MVC dispatch lifecycle and source identity through the packaged agent:
//! Final status is observed at normal outer standard servlet exit, after post-chain filters,
//! even for buffered responses. Pending container errors, escaping exceptions and asynchronous
//! responses retain only provisional status evidence.
//! Application frames carry the matched `.java` source file and line even when the JVM starts
//! from a directory unrelated to the repository.

#![cfg(unix)]
#![allow(missing_docs, reason = "integration test symbols are executable fixtures")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "controlled fixture processes and temporary project data are asserted directly"
)]

use std::fs;
use std::io::{BufRead as _, Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;
use xtrace_domain::ContentHash;
use xtrace_protocol::generated::agent::{RecordingEvent, RecordingEventKind, SourceBinding};
use xtrace_store::decode_compressed_segment;

struct RunProcess {
    child: Child,
}

impl Drop for RunProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            if let Ok(pid) = i32::try_from(self.child.id()) {
                if let Some(pid) = rustix::process::Pid::from_raw(pid) {
                    let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
                }
            }
            let _ = self.child.wait();
        }
    }
}

struct StopDaemon<'a> {
    repo: &'a Path,
    data_home: &'a Path,
}

impl Drop for StopDaemon<'_> {
    fn drop(&mut self) {
        let _ = Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["stop", "--project-dir"])
            .arg(self.repo)
            .env("XTRACE_DATA_HOME", self.data_home)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

struct Captured {
    detail: Value,
    events: Vec<Value>,
    recording_count: usize,
    stderr: String,
    wire_events: Vec<RecordingEvent>,
    copied_source: Vec<u8>,
}

fn field<'a>(value: &'a Value, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| value.get(*name)).filter(|found| !found.is_null())
}

#[test]
fn redirect_status_and_source_identity_are_recorded_from_an_unrelated_working_directory() {
    assert_redirect(run_redirect("run"));
}

#[test]
fn record_source_identity_uses_the_project_when_the_jvm_starts_elsewhere() {
    assert_redirect(run_redirect("record"));
}

#[test]
fn restart_source_identity_uses_the_project_when_the_jvm_starts_elsewhere() {
    assert_redirect(run_redirect("restart"));
}

fn assert_redirect(captured: Captured) {
    assert_eq!(
        captured.recording_count, 1,
        "exactly one recording for the one request; stderr: {}",
        captured.stderr
    );
    let outcome = &captured.detail["outcome"];
    assert_eq!(
        field(outcome, &["kind"]).and_then(Value::as_str),
        Some("responded"),
        "outcome: {outcome}; stderr: {}",
        captured.stderr
    );
    assert_eq!(
        field(outcome, &["httpStatus", "http_status"]).and_then(Value::as_u64),
        Some(302),
        "the recorded status must be the committed redirect at outer servlet exit: \
         {outcome}"
    );
    let request = captured
        .events
        .iter()
        .find(|event| event["symbol"].as_str().is_some_and(|s| s.starts_with("http.request ")))
        .expect("request event");
    assert_eq!(request["symbol"], "http.request POST /__fixture/redirect");
    let frame = captured
        .events
        .iter()
        .find(|event| {
            event["kind"].as_str().is_some_and(|kind| kind.ends_with("frame_enter"))
                && event["symbol"] == "FixtureAdminController.redirect"
        })
        .unwrap_or_else(|| panic!("controller frame missing: {:?}", captured.events));
    let source = &frame["source"];
    assert!(
        source["path"].as_str().is_some_and(|path| path.ends_with("FixtureAdminController.java")),
        "the controller frame must carry its matched source file: {frame}"
    );
    assert!(
        field(source, &["startLine", "start_line"]).and_then(Value::as_u64).is_some_and(|l| l >= 1),
        "the controller frame must carry a start line: {frame}"
    );
    assert_eq!(
        source["path"],
        "adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture/FixtureAdminController.java",
        "the controller frame must carry its exact project-relative source path: {frame}"
    );
    assert_eq!(frame["source_binding"], "observed_unattested");
    let source_text = std::str::from_utf8(&captured.copied_source).expect("copied Java source");
    // javac's line table starts this method at its first executable statement.
    let method_line = source_text
        .lines()
        .position(|line| line.contains("return new RedirectView("))
        .expect("redirect executable line")
        + 1;
    assert_eq!(
        field(source, &["startLine", "start_line"]).and_then(Value::as_u64),
        Some(method_line as u64),
        "the method extent must begin on its recorded executable line: {frame}"
    );
    let wire_frame = captured
        .wire_events
        .iter()
        .find(|event| {
            event.kind == RecordingEventKind::FrameEnter as i32
                && event.symbol == "FixtureAdminController.redirect"
        })
        .expect("persisted controller frame");
    assert_eq!(wire_frame.source_binding, SourceBinding::ObservedUnattested as i32);
    let wire_source = wire_frame.source.as_ref().expect("persisted source range");
    assert_eq!(wire_source.path, source["path"].as_str().unwrap());
    assert_eq!(wire_source.start_line as u64, method_line as u64);
    assert_eq!(wire_source.content_hash.len(), 32);
    assert_eq!(&wire_source.content_hash[..], blake3::hash(&captured.copied_source).as_bytes());
    assert_complete_single_recording(&captured);
}

fn assert_complete_single_recording(captured: &Captured) {
    assert_eq!(captured.recording_count, 1, "stderr: {}", captured.stderr);
    assert_eq!(captured.detail["status"], "complete", "{}", captured.detail);
    for prefix in ["http.request ", "http.response "] {
        assert_eq!(
            captured
                .events
                .iter()
                .filter(|event| {
                    event["symbol"].as_str().is_some_and(|symbol| symbol.starts_with(prefix))
                })
                .count(),
            1,
            "one root marker for {prefix}: {:?}",
            captured.events
        );
    }
}

#[test]
fn forward_and_include_keep_the_outer_root_until_the_final_rendered_status() {
    for (path, status) in [("forward", 202), ("include", 207)] {
        let captured = run_request("GET", &format!("/__fixture/lifecycle/{path}"), status);
        assert_complete_single_recording(&captured);
        assert_final_status(&captured, status);
        for symbol in ["LifecycleController.inner", "LifecycleController.afterNested"] {
            assert!(
                captured
                    .events
                    .iter()
                    .any(|event| { event["symbol"] == symbol && event["kind"] == "frame_enter" }),
                "{path} must retain {symbol}: {:?}",
                captured.events
            );
        }
        let after = captured
            .events
            .iter()
            .position(|event| {
                event["symbol"] == "LifecycleController.afterNested"
                    && event["kind"] == "frame_exit"
            })
            .expect("outer view continued after nested dispatch");
        let response = captured
            .events
            .iter()
            .position(|event| {
                event["symbol"].as_str().is_some_and(|symbol| symbol.starts_with("http.response "))
            })
            .expect("response event");
        assert!(after < response, "root must close after the outer view has continued");
    }
}

#[test]
fn resolved_exception_has_the_final_buffered_error_view_status() {
    let captured = run_request("GET", "/__fixture/lifecycle/mapped", 422);
    assert_complete_single_recording(&captured);
    assert_final_status(&captured, 422);
    assert!(captured.events.iter().any(|event| {
        event["symbol"] == "LifecycleController.mapped" && event["kind"] == "frame_throw"
    }));
}

#[test]
fn async_is_one_complete_recording_with_an_unobserved_outcome() {
    let captured = run_request("GET", "/__fixture/lifecycle/async", 206);
    assert_complete_single_recording(&captured);
    assert_eq!(captured.detail["outcome"]["kind"], "unobserved");
    assert!(captured.detail["outcome"]["httpStatus"].is_null());
    assert_provisional(&captured, 200);
}

#[test]
fn post_chain_filter_status_is_final_304_at_outer_servlet_exit() {
    let captured = run_request("GET", "/__fixture/lifecycle/post-filter", 304);
    assert_complete_single_recording(&captured);
    assert_final_status(&captured, 304);
}

#[test]
fn pending_container_error_handling_keeps_status_provisional_without_a_second_recording() {
    let captured = run_request("GET", "/__fixture/lifecycle/send-error", 418);
    assert_complete_single_recording(&captured);
    assert_provisional(&captured, 418);
}

#[test]
fn record_session_captures_the_final_buffered_status_of_a_resolved_exception() {
    let captured = run_request_with_launcher("GET", "/__fixture/lifecycle/mapped", 422, "record");
    assert_complete_single_recording(&captured);
    assert_final_status(&captured, 422);
    assert!(captured.events.iter().any(|event| {
        event["symbol"] == "LifecycleController.mapped" && event["kind"] == "frame_throw"
    }));
}

fn assert_final_status(captured: &Captured, status: u16) {
    assert_eq!(captured.detail["outcome"]["kind"], "responded");
    assert_eq!(captured.detail["outcome"]["httpStatus"], status);
    let label = format!("http.response {status}");
    assert!(
        captured.events.iter().any(|event| event["symbol"] == label),
        "replay must retain the final response status"
    );
    let wire_response = captured
        .wire_events
        .iter()
        .find(|event| event.kind == RecordingEventKind::Response as i32)
        .expect("persisted response event");
    assert_eq!(wire_response.symbol, label);
    assert_eq!(
        wire_response.interaction.as_ref().expect("response interaction").path,
        status.to_string()
    );
}

fn assert_provisional(captured: &Captured, status: u16) {
    assert_eq!(captured.detail["outcome"]["kind"], "unobserved");
    assert!(captured.detail["outcome"]["httpStatus"].is_null());
    let label = format!(
        "http.response unavailable; final status not observed; observed status was \
         {status} (provisional)"
    );
    assert!(
        captured.events.iter().any(|event| event["symbol"] == label),
        "replay must retain the explicitly provisional observation"
    );
    let wire_response = captured
        .wire_events
        .iter()
        .find(|event| event.kind == RecordingEventKind::Response as i32)
        .expect("persisted response event");
    assert_eq!(wire_response.symbol, label);
    assert_eq!(
        wire_response.interaction.as_ref().expect("response interaction").path,
        "unavailable"
    );
}

#[test]
fn committed_outer_servlet_status_is_authoritative() {
    let captured = run_request("GET", "/__fixture/boundary/committed", 209);
    assert_complete_single_recording(&captured);
    assert_eq!(captured.detail["outcome"]["kind"], "responded");
    assert_eq!(captured.detail["outcome"]["httpStatus"], 209);
}

#[test]
fn buffered_outer_servlet_status_is_final_on_normal_return_without_pending_error() {
    let captured = run_request("GET", "/__fixture/boundary/uncommitted", 210);
    assert_complete_single_recording(&captured);
    assert_final_status(&captured, 210);
}

#[test]
fn later_container_error_page_can_change_the_provisional_status() {
    let captured = run_request("GET", "/__fixture/boundary/send-error", 451);
    assert_complete_single_recording(&captured);
    assert_provisional(&captured, 418);
}

fn run_redirect(mode: &str) -> Captured {
    run_request_with_launcher("POST", "/__fixture/redirect", 302, mode)
}

fn run_request(method: &str, path: &str, client_status: u16) -> Captured {
    run_request_with_launcher(method, path, client_status, "run")
}

fn run_request_with_launcher(method: &str, path: &str, client_status: u16, mode: &str) -> Captured {
    let root = temp_root();
    let repo = root.path().join("repository");
    let elsewhere = root.path().join("unrelated working directory");
    let data_home = root.path().join("data home");
    fs::create_dir_all(&repo).expect("repository");
    fs::create_dir_all(&elsewhere).expect("unrelated working directory");
    let init = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["init", "--project-dir"])
        .arg(&repo)
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("initialize project");
    assert!(init.status.success(), "init failed: {}", String::from_utf8_lossy(&init.stderr));
    copy_fixture_sources(&repo);
    let project_root = project_data_root(&data_home);

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let agent =
        workspace.join("adapters/java/agent-bootstrap/build/agent-dist/xtrace-java-agent.jar");
    let fixture =
        workspace.join("adapters/java/spring-fixture/build/libs/xtrace-spring-fixture.jar");
    assert!(agent.is_file(), "Gradle agentDist must run before this test");
    assert!(fixture.is_file(), "Gradle fixtureBootJar must run before this test");

    // The JVM starts in a directory that holds no sources and is not under the repository: the
    // operator-named project directory, not the working directory, is where source roots resolve.
    let capture_flags = [
        "--app-package",
        "dev.xtrace.fixture",
        "--source-root",
        "adapters/java/spring-fixture/src/main/java",
    ];
    let _daemon = (mode != "run").then(|| StopDaemon { repo: &repo, data_home: &data_home });
    let mut launch = if mode == "run" {
        let mut command = Command::new(env!("CARGO_BIN_EXE_xtrace"));
        command.args(["run", "--project-dir"]).arg(&repo).arg("--java-agent").arg(&agent);
        command.args(capture_flags).args(["--", "java"]);
        command
    } else {
        // Both invocations use a non-canonical spelling and a CLI working directory unrelated
        // to the project. The separately launched JVM has no source tree in its user.dir.
        let project_arg = repo.join(".");
        let mut armed = Value::Null;
        for command in if mode == "restart" { vec!["record", "restart"] } else { vec!["record"] } {
            let output = Command::new(env!("CARGO_BIN_EXE_xtrace"))
                .current_dir(&elsewhere)
                .arg(command)
                .arg("--project-dir")
                .arg(&project_arg)
                .args(capture_flags)
                .env("XTRACE_DATA_HOME", &data_home)
                .output()
                .expect("arm detached capture");
            assert!(
                output.status.success(),
                "{command}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let doc: Value = serde_json::from_slice(&output.stdout).expect("lifecycle JSON");
            armed = if command == "restart" { doc["started"].clone() } else { doc };
            let bootstrap = Path::new(armed["bootstrap_path"].as_str().expect("bootstrap path"));
            let capture: Value = serde_json::from_slice(
                &fs::read(bootstrap.with_file_name("capture.json")).expect("capture document"),
            )
            .expect("capture JSON");
            assert_eq!(
                capture["project_dir"],
                serde_json::json!(repo.canonicalize().expect("canonical project"))
            );
        }
        let bootstrap = armed["bootstrap_path"].as_str().expect("bootstrap path");
        let mut command = Command::new("java");
        command.arg(format!("-javaagent:{}={bootstrap}", agent.display()));
        command
    };
    let child = launch
        .current_dir(&elsewhere)
        .arg("-jar")
        .arg(&fixture)
        .arg("--server.port=0")
        // The fixture defaults to WARN; enable only the bound-port startup signal.
        .arg("--logging.level.org.springframework.boot.tomcat.TomcatWebServer=INFO")
        .env("XTRACE_DATA_HOME", &data_home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start instrumented application");
    let mut process = RunProcess { child };
    let stdout = process.child.stdout.take().expect("xtrace stdout");
    let (lines_tx, lines_rx) = std::sync::mpsc::channel();
    let stdout = thread::spawn(move || drain_fixture_stdout(stdout, lines_tx));
    let stderr = process.child.stderr.take().expect("xtrace stderr");
    let stderr = thread::spawn(move || drain(stderr));

    let port = wait_for_fixture(&lines_rx);
    let response = http_request(port, method, path);
    assert!(
        response.starts_with(format!("HTTP/1.1 {client_status}").as_bytes()),
        "fixture must answer {client_status} for {path}: {}",
        String::from_utf8_lossy(&response)
    );
    wait_for_complete_recording(&project_root);

    let pid = rustix::process::Pid::from_raw(process.child.id() as i32).expect("CLI process ID");
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).expect("signal xtrace run");
    process.child.wait().expect("wait for signal shutdown");
    let _stdout = stdout.join().expect("join stdout");
    let stderr = stderr.join().expect("join stderr");

    if mode != "run" {
        let stopped = Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["stop", "--project-dir"])
            .arg(&repo)
            .env("XTRACE_DATA_HOME", &data_home)
            .output()
            .expect("stop detached daemon");
        assert!(stopped.status.success(), "stop: {}", String::from_utf8_lossy(&stopped.stderr));
    }
    let list = cli(&["recording", "list"], &repo, &data_home);
    let list: Value = serde_json::from_slice(&list.stdout).expect("recording list JSON");
    let recordings = list["recordings"].as_array().expect("recordings");
    let recording_id = recordings[0]["recording_id"].as_str().expect("recording id").to_owned();

    let mut detail = Value::Null;
    let mut events = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..20 {
        let mut args = vec!["recording", "show", recording_id.as_str(), "--limit", "1000"];
        if let Some(cursor) = cursor.as_deref() {
            args.extend(["--cursor", cursor]);
        }
        let output = cli(&args, &repo, &data_home);
        assert!(
            output.status.success(),
            "recording show failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let page: Value = serde_json::from_slice(&output.stdout).expect("recording detail JSON");
        events.extend(page["events"].as_array().expect("events").iter().cloned());
        cursor = page["next_cursor"].as_str().map(str::to_owned);
        if detail.is_null() {
            detail = page;
        }
        if cursor.is_none() {
            break;
        }
    }
    assert!(cursor.is_none(), "recording did not terminate within 20 pages");
    let wire_events = persisted_events(&project_root);
    let copied_source = fs::read(repo.join(
        "adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture/FixtureAdminController.java",
    ))
    .expect("copied controller source");
    Captured {
        wire_events,
        copied_source,
        detail,
        events,
        recording_count: recordings.len(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    }
}

// The public replay projection intentionally omits hashes; inspect the verified XTF evidence.
fn persisted_events(project_root: &Path) -> Vec<RecordingEvent> {
    let database = rusqlite::Connection::open(project_root.join("metadata.sqlite3"))
        .expect("recording metadata");
    let mut query = database
        .prepare("SELECT object_hash FROM recording_segments ORDER BY segment_ordinal")
        .expect("segment query");
    let hashes = query.query_map([], |row| row.get::<_, Vec<u8>>(0)).expect("segment hashes");
    let mut events = Vec::new();
    for hash in hashes {
        let hash = hash.expect("segment hash");
        let expected = ContentHash::from_digest_bytes(&hash).expect("32-byte segment digest");
        let hex = expected.to_string();
        let hex = hex.strip_prefix("b3:").expect("BLAKE3 identity");
        let object =
            project_root.join("objects/b3").join(&hex[..2]).join(format!("{}.xtf.zst", &hex[2..]));
        let decoded = decode_compressed_segment(&fs::read(object).expect("XTF object"), expected)
            .expect("verified XTF segment");
        events.extend(
            decoded
                .events()
                .iter()
                .map(|envelope| envelope.event.clone().expect("typed recording event")),
        );
    }
    events
}

fn cli(args: &[&str], repo: &Path, data_home: &Path) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtrace"));
    command.arg(args[0]).arg(args[1]).arg("--project-dir").arg(repo).args(&args[2..]);
    command.env("XTRACE_DATA_HOME", data_home).output().expect("run xtrace")
}

fn project_data_root(data_home: &Path) -> PathBuf {
    let projects = data_home.join("projects");
    let mut entries: Vec<PathBuf> = fs::read_dir(&projects)
        .expect("projects directory")
        .map(|entry| entry.expect("project entry").path())
        .collect();
    assert_eq!(entries.len(), 1, "one project data directory expected");
    entries.remove(0)
}

fn wait_for_complete_recording(project_root: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(database) = rusqlite::Connection::open(project_root.join("metadata.sqlite3")) {
            let count: i64 = database
                .query_row("SELECT COUNT(*) FROM recordings WHERE status = 'complete'", [], |row| {
                    row.get(0)
                })
                .unwrap_or(0);
            if count >= 1 {
                return;
            }
        }
        assert!(Instant::now() < deadline, "no complete recording was persisted");
        thread::sleep(Duration::from_millis(50));
    }
}

fn temp_root() -> TempDir {
    let base = std::env::temp_dir().canonicalize().expect("temporary root");
    tempfile::Builder::new()
        .prefix("xtrace redirect ")
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir_in(base)
        .expect("temporary test root")
}

fn copy_fixture_sources(repo: &Path) {
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture");
    let destination = repo.join("adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture");
    fs::create_dir_all(&destination).expect("create fixture source directory");
    for name in [
        "FixtureAdminController.java",
        "OrderRepository.java",
        "LifecycleController.java",
        "LifecycleStatusFilter.java",
        "ServletBoundaryController.java",
    ] {
        fs::copy(source_root.join(name), destination.join(name)).expect("copy fixture source");
    }
}

fn wait_for_fixture(lines: &std::sync::mpsc::Receiver<Vec<u8>>) -> u16 {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("Spring fixture readiness deadline elapsed");
        let line = lines
            .recv_timeout(remaining)
            .expect("Spring fixture did not report its bound port before the readiness deadline");
        // Boot 4.1.1 logs the connector's local port only after it has started.
        let line = String::from_utf8_lossy(&line);
        if let Some((_, address)) = line.split_once("Tomcat started on port ") {
            if let Some((port, _)) = address.split_once(" (http)") {
                let port = port.parse::<u16>().expect("Spring fixture bound port");
                assert_ne!(port, 0, "Spring fixture must report its actual bound port");
                return port;
            }
        }
    }
}

fn http_request(port: u16, method: &str, path: &str) -> Vec<u8> {
    let mut stream =
        std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect Spring fixture");
    stream.set_read_timeout(Some(Duration::from_secs(10))).expect("read timeout");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    )
    .expect("write request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    response
}

fn drain_fixture_stdout(reader: impl Read, lines: std::sync::mpsc::Sender<Vec<u8>>) -> Vec<u8> {
    let mut reader = std::io::BufReader::new(reader);
    let mut bytes = Vec::new();
    loop {
        let mut line = Vec::new();
        if reader.read_until(b'\n', &mut line).expect("read fixture stdout") == 0 {
            break;
        }
        bytes.extend_from_slice(&line);
        let _ = lines.send(line);
    }
    bytes
}

fn drain(mut reader: impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = reader.read_to_end(&mut bytes);
    bytes
}
