//! Journey: `xtrace run --capture-depth focused --app-package ...` on the Spring fixture, read back
//! through the recording read API (`xtrace recording show`).
//!
//! The launch flags write the private `capture.json`; the Java agent reads scope and mode from it
//! and the daemon arms the session from the same file. The read API then shows the armed policy
//! through the recording's event cap (131,072 focused versus 16,384 standard) and, for focused
//! capture, either `line_cursor` events that carry an observed line or, while the Java agent's line
//! probes cannot wrap a method, the declared `not-transformed` gap that keeps the recording partial.

#![cfg(unix)]
#![allow(missing_docs, reason = "integration test symbols are executable fixtures")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "controlled fixture processes and temporary project data are asserted directly"
)]

use std::fs;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;

struct RunProcess {
    child: Child,
    stdout: Option<thread::JoinHandle<Vec<u8>>>,
    stderr: Option<thread::JoinHandle<Vec<u8>>>,
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

struct Captured {
    detail_pages: Vec<Value>,
    events: Vec<Value>,
    stderr: String,
}

#[test]
fn focused_run_arms_the_session_and_states_line_event_status() {
    let captured = run_fixture(&[
        "--capture-depth",
        "focused",
        "--app-package",
        "dev.xtrace.fixture",
        "--source-root",
        "adapters/java/spring-fixture/src/main/java",
    ]);
    let first = &captured.detail_pages[0];
    // The armed policy is visible through the read API as the cap in force.
    assert_eq!(
        first["capacity"]["eventCap"], 131_072,
        "a focused launch must be served under the focused cap; stderr: {}",
        captured.stderr
    );
    // NOT ASSERTED: that `capture_policy_not_armed` is absent. The read API does not carry
    // recording limitations yet (BeginRecording has no limitations field; see
    // requests/RC2-FC2-to-FC1-limitations.md), so such an assertion would pass vacuously.
    let in_scope_frames: Vec<&Value> = captured
        .events
        .iter()
        .filter(|event| {
            event["kind"].as_str().is_some_and(|kind| kind.ends_with("frame_enter"))
                && event["symbol"].as_str().is_some_and(|s| s.starts_with("Order"))
        })
        .collect();
    assert!(!in_scope_frames.is_empty(), "in-scope application frames were not captured");
    let lines: Vec<&Value> = captured
        .events
        .iter()
        .filter(|event| event["kind"].as_str().is_some_and(|kind| kind.ends_with("line_cursor")))
        .collect();
    for line in &lines {
        assert!(
            line["line"].as_u64().is_some_and(|number| number > 0),
            "a line event must carry an observed line number: {line}"
        );
    }
    if lines.is_empty() {
        // Line events have not reached the read API for this build of the Java agent: its line
        // probes skip methods they cannot wrap. The absence must be declared, never silent:
        // the agent emits a not-transformed gap, the read API surfaces it as incomplete
        // evidence, and the recording is not reported as complete.
        assert!(
            captured.events.iter().any(|event| {
                event["kind"].as_str().is_some_and(|kind| kind.ends_with("gap"))
                    && event["symbol"]
                        .as_str()
                        .is_some_and(|symbol| symbol.ends_with("gap.not-transformed"))
            }),
            "focused capture without line events must declare a not-transformed gap; kinds: {:?}",
            captured.events.iter().map(|event| event["kind"].clone()).collect::<Vec<_>>()
        );
        assert_ne!(
            first["completion"], "complete",
            "a declared gap must keep the recording partial"
        );
        assert!(
            first["incomplete_evidence"]
                .as_array()
                .expect("incomplete evidence")
                .iter()
                .any(|entry| entry.as_str().is_some_and(|e| e.starts_with("gap_event_sequence"))),
            "the declared gap must be listed as incomplete evidence"
        );
    }
}

#[test]
fn standard_run_keeps_the_standard_cap_and_emits_no_line_events() {
    let captured = run_fixture(&["--app-package", "dev.xtrace.fixture"]);
    assert_eq!(
        captured.detail_pages[0]["capacity"]["eventCap"], 16_384,
        "a default launch must stay on the standard cap"
    );
    assert!(
        !captured
            .events
            .iter()
            .any(|event| event["kind"].as_str().is_some_and(|kind| kind.ends_with("line_cursor"))),
        "standard capture must not emit line events"
    );
    assert!(
        captured
            .events
            .iter()
            .any(|event| event["symbol"].as_str().is_some_and(|s| s.contains("OrderController"))),
        "standard capture still records application frames"
    );
}

#[test]
fn out_of_scope_app_package_captures_no_application_frames() {
    let captured = run_fixture(&["--app-package", "com.nonexistent.app"]);
    let order_frames: Vec<&Value> = captured
        .events
        .iter()
        .filter(|event| {
            event["symbol"].as_str().is_some_and(|symbol| symbol.contains("Order"))
                && event["kind"].as_str().is_some_and(|kind| kind.ends_with("frame_enter"))
        })
        .collect();
    assert!(
        order_frames.is_empty(),
        "an app package that matches no class must not capture Order frames: {order_frames:?}"
    );
}

#[test]
fn invalid_capture_flags_fail_before_any_launch() {
    for bad in [
        &["--capture-depth", "deep"][..],
        &["--app-package", "not a package"][..],
        &["--app-package", "java.util"][..],
        &["--source-root", "../escape"][..],
        &["--launcher", "maven"][..],
    ] {
        let root = temp_root();
        let output = Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["run", "--project-dir"])
            .arg(root.path())
            .args(["--java-agent", "/nonexistent/agent.jar"])
            .args(bad)
            .args(["--", "java", "-version"])
            .output()
            .expect("run xtrace");
        assert_eq!(output.status.code(), Some(2), "{bad:?} must be an argument error");
    }
}

fn run_fixture(flags: &[&str]) -> Captured {
    let root = temp_root();
    let repo = root.path().join("repository with spaces");
    let data_home = root.path().join("data home");
    fs::create_dir_all(&repo).expect("repository");
    let init = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["init", "--project-dir"])
        .arg(&repo)
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("initialize project");
    assert!(init.status.success(), "init failed: {}", String::from_utf8_lossy(&init.stderr));
    copy_fixture_sources(&repo);
    let project_id =
        serde_json::from_slice::<Value>(&init.stdout).expect("init JSON")["project_id"]
            .as_str()
            .expect("project id")
            .to_string();
    let project_root = data_home.join("projects").join(&project_id);

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let agent =
        workspace.join("adapters/java/agent-bootstrap/build/agent-dist/xtrace-java-agent.jar");
    let fixture =
        workspace.join("adapters/java/spring-fixture/build/libs/xtrace-spring-fixture.jar");
    assert!(agent.is_file(), "Gradle agentDist must run before this test");
    assert!(fixture.is_file(), "Gradle fixtureBootJar must run before this test");
    let port = free_port();

    let mut child = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["run", "--project-dir"])
        .arg(&repo)
        .arg("--java-agent")
        .arg(&agent)
        .args(flags)
        .arg("--")
        .arg("java")
        .arg("-jar")
        .arg(&fixture)
        .arg(format!("--server.port={port}"))
        .env("XTRACE_DATA_HOME", &data_home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start xtrace run");
    let stdout = child.stdout.take().expect("xtrace stdout");
    let stderr = child.stderr.take().expect("xtrace stderr");
    let mut process = RunProcess {
        child,
        stdout: Some(thread::spawn(move || drain(stdout))),
        stderr: Some(thread::spawn(move || drain(stderr))),
    };

    wait_for_fixture(port);
    let response = post_order(port);
    assert!(
        response.starts_with(b"HTTP/1.1 201"),
        "fixture returned {}",
        String::from_utf8_lossy(&response)
    );
    wait_for_complete_recording(&project_root);

    let pid = rustix::process::Pid::from_raw(process.child.id() as i32).expect("CLI process ID");
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).expect("signal xtrace run");
    process.child.wait().expect("wait for signal shutdown");
    let _ = process.stdout.take().expect("stdout thread").join();
    let stderr = process.stderr.take().expect("stderr thread").join().expect("join stderr");

    let list = cli(&["recording", "list"], &repo, &data_home);
    let list: Value = serde_json::from_slice(&list.stdout).expect("recording list JSON");
    let recording_id =
        list["recordings"][0]["recording_id"].as_str().expect("recording id").to_owned();

    let mut detail_pages = Vec::new();
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
        detail_pages.push(page);
        if cursor.is_none() {
            break;
        }
    }
    assert!(cursor.is_none(), "recording did not terminate within 20 pages");
    Captured { detail_pages, events, stderr: String::from_utf8_lossy(&stderr).into_owned() }
}

fn cli(args: &[&str], repo: &Path, data_home: &Path) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtrace"));
    command.arg(args[0]).arg(args[1]).arg("--project-dir").arg(repo).args(&args[2..]);
    command.env("XTRACE_DATA_HOME", data_home).output().expect("run xtrace")
}

fn wait_for_complete_recording(project_root: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(database) = rusqlite::Connection::open(project_root.join("metadata.sqlite3")) {
            let count: i64 = database
                .query_row(
                    "SELECT COUNT(*) FROM recordings WHERE status IN ('complete', 'partial')",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            if count >= 1 {
                return;
            }
        }
        assert!(Instant::now() < deadline, "no finished recording was persisted");
        thread::sleep(Duration::from_millis(50));
    }
}

fn temp_root() -> TempDir {
    let base = std::env::temp_dir().canonicalize().expect("temporary root");
    tempfile::Builder::new()
        .prefix("xtrace capture ")
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir_in(base)
        .expect("temporary test root")
}

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("port address")
        .port()
}

fn copy_fixture_sources(repo: &Path) {
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture");
    let destination = repo.join("adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture");
    fs::create_dir_all(&destination).expect("create fixture source directory");
    for name in ["OrderController.java", "OrderService.java", "OrderRepository.java"] {
        fs::copy(source_root.join(name), destination.join(name)).expect("copy fixture source");
    }
}

fn wait_for_fixture(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "Spring fixture did not become ready");
        thread::sleep(Duration::from_millis(30));
    }
}

fn post_order(port: u16) -> Vec<u8> {
    let body = br#"{"description":"capture journey","bodyCanary":"safe","errorCanary":""}"#;
    let mut stream =
        std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect Spring fixture");
    stream.set_read_timeout(Some(Duration::from_secs(10))).expect("read timeout");
    write!(
        stream,
        "POST /orders HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .expect("write request");
    stream.write_all(body).expect("write body");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    response
}

fn drain(mut reader: impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = reader.read_to_end(&mut bytes);
    bytes
}
