//! Real Spring MVC journeys for two behaviours a Post/Redirect/Get application needs:
//! the recorded HTTP outcome is the status the response finally carried (a redirect view sets 302
//! after the handler adapter returned), and application frames carry the matched `.java` source
//! file and line even when the JVM is started from a directory unrelated to the repository.

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
    detail: Value,
    events: Vec<Value>,
    recording_count: usize,
    stderr: String,
}

fn field<'a>(value: &'a Value, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| value.get(*name)).filter(|found| !found.is_null())
}

#[test]
fn redirect_status_and_source_identity_are_recorded_from_an_unrelated_working_directory() {
    let captured = run_redirect();
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
        "the recorded status must be the redirect the client saw, not the handler-time default: \
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
}

fn run_redirect() -> Captured {
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
    let port = free_port();

    // The JVM starts in a directory that holds no sources and is not under the repository: the
    // operator-named project directory, not the working directory, is where source roots resolve.
    let child = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .current_dir(&elsewhere)
        .args(["run", "--project-dir"])
        .arg(&repo)
        .arg("--java-agent")
        .arg(&agent)
        .args([
            "--app-package",
            "dev.xtrace.fixture",
            "--source-root",
            "adapters/java/spring-fixture/src/main/java",
        ])
        .arg("--")
        .arg("java")
        .arg("-jar")
        .arg(&fixture)
        .arg(format!("--server.port={port}"))
        .env("XTRACE_DATA_HOME", &data_home)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start xtrace run");
    let mut process = RunProcess { child };
    let stderr = process.child.stderr.take().expect("xtrace stderr");
    let stderr = thread::spawn(move || drain(stderr));

    wait_for_fixture(port);
    let response = post_redirect(port);
    assert!(
        response.starts_with(b"HTTP/1.1 302"),
        "fixture must answer with a redirect: {}",
        String::from_utf8_lossy(&response)
    );
    wait_for_complete_recording(&project_root);

    let pid = rustix::process::Pid::from_raw(process.child.id() as i32).expect("CLI process ID");
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).expect("signal xtrace run");
    process.child.wait().expect("wait for signal shutdown");
    let stderr = stderr.join().expect("join stderr");

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
    Captured {
        detail,
        events,
        recording_count: recordings.len(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    }
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
        .prefix("xtrace redirect ")
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
    for name in ["FixtureAdminController.java", "OrderRepository.java"] {
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

fn post_redirect(port: u16) -> Vec<u8> {
    let mut stream =
        std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect Spring fixture");
    stream.set_read_timeout(Some(Duration::from_secs(10))).expect("read timeout");
    write!(
        stream,
        "POST /__fixture/redirect HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    )
    .expect("write request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    response
}

fn drain(mut reader: impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = reader.read_to_end(&mut bytes);
    bytes
}
