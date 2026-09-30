#![cfg(unix)]
#![allow(missing_docs, reason = "integration test symbols are executable fixtures")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "controlled fixture processes and temporary project data are asserted directly"
)]

use std::fs;
use std::io::BufRead as _;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use serde_json::Value;
use tempfile::TempDir;
use xtrace_store::verify_compressed_segment;

struct RunProcess {
    child: Child,
    stdout: Option<thread::JoinHandle<Vec<u8>>>,
    stderr: Option<thread::JoinHandle<Vec<u8>>>,
}

struct ViewerProcess {
    child: Child,
    stderr: Option<thread::JoinHandle<Vec<u8>>>,
}

impl Drop for ViewerProcess {
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

#[test]
fn run_launches_spring_fixture_captures_selected_root_and_forwards_shutdown() {
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
    let project_id =
        serde_json::from_slice::<Value>(&init.stdout).expect("init JSON")["project_id"]
            .as_str()
            .expect("project id")
            .to_string();
    let project_root = data_home.join("projects").join(project_id);

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let agent =
        workspace.join("adapters/java/agent-bootstrap/build/agent-dist/xtrace-java-agent.jar");
    let fixture =
        workspace.join("adapters/java/spring-fixture/build/libs/xtrace-spring-fixture.jar");
    assert!(agent.is_file(), "Gradle agentDist must run before this test");
    assert!(fixture.is_file(), "Gradle fixtureBootJar must run before this test");
    let port = free_port();

    let mut command = Command::new(env!("CARGO_BIN_EXE_xtrace"));
    command
        .args(["run", "--project-dir"])
        .arg(&repo)
        .arg("--java-agent")
        .arg(&agent)
        .arg("--")
        .arg("java")
        .arg("-jar")
        .arg(&fixture)
        .arg(format!("--server.port={port}"))
        .env("XTRACE_DATA_HOME", &data_home)
        .env("JAVA_TOOL_OPTIONS", "-javaagent:/xtrace-env-canary/JAVA_TOOL_OPTIONS")
        .env("JDK_JAVA_OPTIONS", "-javaagent:/xtrace-env-canary/JDK_JAVA_OPTIONS")
        .env("_JAVA_OPTIONS", "-javaagent:/xtrace-env-canary/_JAVA_OPTIONS")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("start xtrace run");
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
    let logical = wait_for_segment(&project_root);
    assert!(logical.windows(22).any(|bytes| bytes == b"OrderController.create"));
    for canary in
        ["BODY_CANARY_1D4", "AUTH_CANARY_1D4", "COOKIE_CANARY_1D4", "PATH_QUERY_CANARY_1E2"]
    {
        assert!(
            !logical.windows(canary.len()).any(|window| window == canary.as_bytes()),
            "{canary} reached stored XTF"
        );
    }
    let second_response = post_order(port);
    assert!(second_response.starts_with(b"HTTP/1.1 201"));
    wait_for_recording_count(&project_root, 2);

    let cli_pid =
        rustix::process::Pid::from_raw(process.child.id() as i32).expect("CLI process ID");
    rustix::process::kill_process(cli_pid, rustix::process::Signal::TERM)
        .expect("signal xtrace run");
    let status = process.child.wait().expect("wait for signal shutdown");
    assert!(!status.success(), "forwarded SIGTERM unexpectedly produced a successful shell status");
    let stdout = process.stdout.take().expect("stdout thread").join().expect("join stdout");
    let stderr = process.stderr.take().expect("stderr thread").join().expect("join stderr");
    for surface in [&stdout, &stderr] {
        for canary in
            ["BODY_CANARY_1D4", "AUTH_CANARY_1D4", "COOKIE_CANARY_1D4", "PATH_QUERY_CANARY_1E2"]
        {
            assert!(
                !surface.windows(canary.len()).any(|window| window == canary.as_bytes()),
                "{canary} leaked to process output"
            );
        }
        for canary in ["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"] {
            assert!(
                !surface.windows(canary.len()).any(|window| window == canary.as_bytes()),
                "ambient JVM option channel {canary} leaked to process output"
            );
        }
        for canary in [
            "/xtrace-env-canary/JAVA_TOOL_OPTIONS",
            "/xtrace-env-canary/JDK_JAVA_OPTIONS",
            "/xtrace-env-canary/_JAVA_OPTIONS",
        ] {
            assert!(
                !surface.windows(canary.len()).any(|window| window == canary.as_bytes()),
                "ambient JVM option value leaked to process output"
            );
        }
    }
    let sessions = project_root.join(".daemon/sessions");
    assert_eq!(fs::read_dir(sessions).expect("sessions directory").count(), 0);
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", port)).is_err(),
        "Java fixture remained after signal shutdown"
    );

    let database = project_root.join("metadata.sqlite3");
    let database_before_queries = fs::read(&database).expect("database snapshot");
    let pointer = repo.join(".xtrace/config.toml");
    let pointer_before_queries = file_state(&pointer);
    let first_page = recording_list_page(&repo, &data_home, None);
    let first_page_again = recording_list_page(&repo, &data_home, None);
    assert!(first_page.status.success(), "recording list failed: {}", diagnostic(&first_page));
    assert!(first_page_again.status.success());
    assert_eq!(first_page.stdout, first_page_again.stdout, "list output must be stable");
    let first_json: Value = serde_json::from_slice(&first_page.stdout).expect("list projection");
    assert_eq!(first_json["schema_version"], 1);
    let first_recording =
        first_json["recordings"][0]["recording_id"].as_str().expect("recording ID");
    let list_cursor = first_json["next_after"].as_str().expect("second page cursor");
    let second_page = recording_list_page(&repo, &data_home, Some(list_cursor));
    assert!(second_page.status.success(), "second page failed: {}", diagnostic(&second_page));
    let second_json: Value = serde_json::from_slice(&second_page.stdout).expect("second page JSON");
    assert_eq!(second_json["recordings"].as_array().expect("recordings").len(), 1);
    assert_ne!(
        first_recording,
        second_json["recordings"][0]["recording_id"].as_str().expect("second recording ID")
    );
    assert_canaries_absent(&first_page.stdout);
    assert_canaries_absent(&second_page.stdout);

    let detail_page = recording_show_page(&repo, &data_home, first_recording, 1, None);
    let detail_page_again = recording_show_page(&repo, &data_home, first_recording, 1, None);
    assert!(detail_page.status.success(), "recording show failed: {}", diagnostic(&detail_page));
    assert_eq!(detail_page.stdout, detail_page_again.stdout, "show output must be stable");
    let detail_json: Value = serde_json::from_slice(&detail_page.stdout).expect("show projection");
    assert_eq!(detail_json["schema_version"], 1);
    assert_eq!(detail_json["status"], "recording");
    assert_eq!(detail_json["unavailable"]["completion"], "unavailable");
    assert_canaries_absent(&detail_page.stdout);
    let show_cursor = detail_json["next_cursor"].as_str().expect("next show cursor");
    let next_detail = recording_show_page(&repo, &data_home, first_recording, 1, Some(show_cursor));
    assert!(next_detail.status.success(), "cursor page failed: {}", diagnostic(&next_detail));
    let next_json: Value = serde_json::from_slice(&next_detail.stdout).expect("continued show");
    assert_eq!(next_json["cursor"], show_cursor);
    let first_sequence = detail_json["events"][0]["sequence"]
        .as_str()
        .expect("first event sequence")
        .parse::<u64>()
        .expect("decimal sequence");
    let next_sequence = next_json["events"][0]["sequence"]
        .as_str()
        .expect("next event sequence")
        .parse::<u64>()
        .expect("decimal sequence");
    assert!(next_sequence > first_sequence);
    assert_canaries_absent(&next_detail.stdout);

    let mut unknown_id = first_recording.as_bytes().to_vec();
    unknown_id[0] = if unknown_id[0] == b'0' { b'1' } else { b'0' };
    let unknown_id = String::from_utf8(unknown_id).expect("UUID is ASCII");
    let unknown = recording_show_page(&repo, &data_home, &unknown_id, 1, None);
    assert!(!unknown.status.success(), "unknown recording should fail");
    assert_canaries_absent(&unknown.stderr);
    assert_eq!(fs::read(&database).expect("database after reads"), database_before_queries);
    assert_eq!(file_state(&pointer), pointer_before_queries);

    let browser_detail = recording_show_page(&repo, &data_home, first_recording, 200, None);
    assert!(browser_detail.status.success(), "browser fixture query failed");
    let browser_detail_json: Value =
        serde_json::from_slice(&browser_detail.stdout).expect("browser expected projection");
    let expected_sequences: Vec<String> = browser_detail_json["events"]
        .as_array()
        .expect("browser expected events")
        .iter()
        .map(|event| event["sequence"].as_str().expect("decimal sequence").to_owned())
        .collect();
    let mut viewer = launch_viewer(&repo, &data_home);
    let readiness = viewer.0;
    let mut browser = Command::new("node");
    browser
        .arg(workspace.join("web/app/scripts/browser-journey.mjs"))
        .arg(first_recording)
        .arg(serde_json::to_string(&expected_sequences).expect("expected sequence JSON"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut browser = browser.spawn().expect("start Chromium browser journey");
    let mut browser_stdin = browser.stdin.take().expect("browser journey stdin");
    browser_stdin
        .write_all(serde_json::to_string(&readiness).expect("readiness JSON").as_bytes())
        .expect("send viewer URL to browser through stdin");
    drop(browser_stdin);
    let browser_result = browser.wait_with_output().expect("wait for browser journey");
    assert!(
        browser_result.status.success(),
        "browser journey failed: {}",
        String::from_utf8_lossy(&browser_result.stderr)
    );
    assert!(String::from_utf8_lossy(&browser_result.stdout).contains("browser journey passed"));
    for canary in
        ["BODY_CANARY_1D4", "AUTH_CANARY_1D4", "COOKIE_CANARY_1D4", "PATH_QUERY_CANARY_1E2"]
    {
        assert!(
            !browser_result.stdout.windows(canary.len()).any(|bytes| bytes == canary.as_bytes())
        );
        assert!(
            !browser_result.stderr.windows(canary.len()).any(|bytes| bytes == canary.as_bytes())
        );
    }
    let stderr = viewer.1.stderr.take().expect("viewer stderr thread");
    let viewer_pid =
        rustix::process::Pid::from_raw(viewer.1.child.id() as i32).expect("viewer process ID");
    rustix::process::kill_process(viewer_pid, rustix::process::Signal::TERM)
        .expect("stop foreground viewer");
    let viewer_status = viewer.1.child.wait().expect("wait for viewer shutdown");
    assert_eq!(
        viewer_status.code(),
        Some(0),
        "viewer SIGTERM should be a clean foreground shutdown"
    );
    let viewer_stderr = stderr.join().expect("join viewer stderr");
    assert_canaries_absent(&viewer_stderr);
    assert_eq!(fs::read(&database).expect("database after viewer"), database_before_queries);
    assert_eq!(file_state(&pointer), pointer_before_queries);

    let reacquired = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["run", "--project-dir"])
        .arg(&repo)
        .arg("--java-agent")
        .arg(&agent)
        .args(["--", "java", "-version"])
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("reacquire project lock after signal shutdown");
    assert_eq!(reacquired.status.code(), Some(0), "signal path left the project locked");
}

#[test]
fn normal_java_leader_exit_kills_same_process_group_descendant() {
    let root = temp_root();
    let repo = root.path().join("repository");
    let data_home = root.path().join("data");
    fs::create_dir_all(&repo).expect("repository");
    let init = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["init", "--project-dir"])
        .arg(&repo)
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("initialize project");
    assert!(init.status.success());
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let agent =
        workspace.join("adapters/java/agent-bootstrap/build/agent-dist/xtrace-java-agent.jar");
    let test_classes = workspace.join("adapters/java/spring-fixture/build/classes/java/test");
    let pid_file = root.path().join("helper.pid");
    let survivor_marker = root.path().join("survivor.marker");

    let output = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["run", "--project-dir"])
        .arg(&repo)
        .arg("--java-agent")
        .arg(&agent)
        .args(["--", "java", "-cp"])
        .arg(test_classes)
        .args(["dev.xtrace.fixture.ProcessGroupLeaderTest"])
        .arg(&pid_file)
        .arg(&survivor_marker)
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("run normal-exit leader fixture");
    assert_eq!(output.status.code(), Some(0), "leader did not preserve zero exit");
    assert!(pid_file.is_file(), "leader did not create helper");
    thread::sleep(Duration::from_millis(2_500));
    assert!(!survivor_marker.exists(), "same-process-group helper survived its leader");
}

#[test]
fn run_preserves_nonzero_java_exit_and_rejects_non_java_before_side_effects() {
    let root = temp_root();
    let repo = root.path().join("repository");
    let data_home = root.path().join("data");
    fs::create_dir_all(&repo).expect("repository");
    let init = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["init", "--project-dir"])
        .arg(&repo)
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("initialize project");
    assert!(init.status.success());
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let agent =
        workspace.join("adapters/java/agent-bootstrap/build/agent-dist/xtrace-java-agent.jar");

    let rejected = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["run", "--project-dir"])
        .arg(&repo)
        .arg("--java-agent")
        .arg(&agent)
        .args(["--", "sh", "-c", "exit 37"])
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("run non-Java preflight");
    assert_eq!(rejected.status.code(), Some(2));
    let project_root = data_home.join("projects").join(
        serde_json::from_slice::<Value>(&init.stdout).expect("init JSON")["project_id"]
            .as_str()
            .expect("project ID"),
    );
    assert!(!project_root.join(".daemon").exists());

    let fake_bin = root.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).expect("fake bin");
    let fake_java = fake_bin.join("java");
    fs::write(&fake_java, b"#!/bin/sh\nprintf 'openjdk version fake\\n' >&2\n")
        .expect("fake Java script");
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(&fake_java, fs::Permissions::from_mode(0o755))
        .expect("fake Java executable");
    let fake_launcher = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["run", "--project-dir"])
        .arg(&repo)
        .arg("--java-agent")
        .arg(&agent)
        .args(["--", "java", "-version"])
        .env("XTRACE_DATA_HOME", &data_home)
        .env("PATH", &fake_bin)
        .output()
        .expect("run against fake Java script");
    assert_eq!(fake_launcher.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&fake_launcher.stderr).contains("native JDK binary"));
    assert!(!project_root.join(".daemon").exists());

    let invalid_agent = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["run", "--project-dir"])
        .arg(&repo)
        .arg("--java-agent")
        .arg(root.path().join("missing-agent.jar"))
        .args(["--", "java", "-version"])
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("run invalid agent preflight");
    assert_eq!(invalid_agent.status.code(), Some(2));
    assert!(!project_root.join(".daemon").exists());

    let invalid_distribution = root.path().join("incomplete agent");
    fs::create_dir_all(invalid_distribution.join("runtime")).expect("empty runtime sibling");
    fs::write(invalid_distribution.join("xtrace-java-agent.jar"), b"PK\x03\x04agent")
        .expect("agent placeholder");
    let invalid_runtime = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["run", "--project-dir"])
        .arg(&repo)
        .arg("--java-agent")
        .arg(invalid_distribution.join("xtrace-java-agent.jar"))
        .args(["--", "java", "-version"])
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("run invalid runtime preflight");
    assert_eq!(invalid_runtime.status.code(), Some(2));
    assert!(!project_root.join(".daemon").exists());

    let failed = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["run", "--project-dir"])
        .arg(&repo)
        .arg("--java-agent")
        .arg(&agent)
        .args(["--", "java", "-xtrace-invalid-option"])
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("run Java nonzero case");
    assert_eq!(
        failed.status.code(),
        Some(1),
        "Java status must be returned directly: {}",
        String::from_utf8_lossy(&failed.stderr)
    );
    assert_eq!(fs::read_dir(project_root.join(".daemon/sessions")).expect("sessions").count(), 0);

    let repeated = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["run", "--project-dir"])
        .arg(&repo)
        .arg("--java-agent")
        .arg(&agent)
        .args(["--", "java", "-version"])
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("run again after lock release");
    assert_eq!(repeated.status.code(), Some(0), "project lock was not released after child exit");
}

#[test]
fn daemon_lock_failure_does_not_launch_the_java_child() {
    let root = temp_root();
    let repo = root.path().join("repository");
    let data_home = root.path().join("data");
    fs::create_dir_all(&repo).expect("repository");
    let init = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["init", "--project-dir"])
        .arg(&repo)
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("initialize project");
    assert!(init.status.success());
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let agent =
        workspace.join("adapters/java/agent-bootstrap/build/agent-dist/xtrace-java-agent.jar");

    let mut daemon = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["daemon", "--project-dir"])
        .arg(&repo)
        .env("XTRACE_DATA_HOME", &data_home)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start project daemon");
    let mut readiness = String::new();
    std::io::BufReader::new(daemon.stdout.take().expect("daemon readiness"))
        .read_line(&mut readiness)
        .expect("read daemon readiness");
    assert!(readiness.contains("daemon_bound"));

    let blocked = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["run", "--project-dir"])
        .arg(&repo)
        .arg("--java-agent")
        .arg(&agent)
        .args(["--", "java", "-version"])
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("run against held project daemon");
    assert_eq!(blocked.status.code(), Some(5), "daemon setup failure should precede Java launch");
    assert!(String::from_utf8_lossy(&blocked.stderr).contains("XTR-CLI-DAEMON-LOCKED"));

    let daemon_pid = rustix::process::Pid::from_raw(daemon.id() as i32).expect("daemon PID");
    rustix::process::kill_process(daemon_pid, rustix::process::Signal::INT)
        .expect("stop project daemon");
    let status = daemon.wait().expect("reap project daemon");
    assert!(status.success(), "daemon shutdown failed: {status}");
}

fn temp_root() -> TempDir {
    let base = std::env::temp_dir().canonicalize().expect("temporary root");
    tempfile::Builder::new().prefix("xtrace run ").tempdir_in(base).expect("temporary test root")
}

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("port address")
        .port()
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
    use std::net::TcpStream;

    let body = br#"{"description":"BODY_CANARY_1D4","bodyCanary":"safe","errorCanary":""}"#;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect Spring fixture");
    stream.set_read_timeout(Some(Duration::from_secs(10))).expect("read timeout");
    write!(stream, "POST /orders?trace=PATH_QUERY_CANARY_1E2 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nAuthorization: Bearer AUTH_CANARY_1D4\r\nCookie: session=COOKIE_CANARY_1D4\r\nContent-Length: {}\r\n\r\n", body.len()).expect("write request");
    stream.write_all(body).expect("write body");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    response
}

fn wait_for_segment(project_root: &Path) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let database = Connection::open(project_root.join("metadata.sqlite3")).expect("SQLite");
        let object_hash = database
            .query_row(
                "SELECT object_hash FROM recording_segments WHERE segment_ordinal = 0 LIMIT 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .ok();
        if let Some(object_hash) = object_hash {
            let hash = object_hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
            let object_path = project_root
                .join("objects/b3")
                .join(&hash[..2])
                .join(format!("{}.xtf.zst", &hash[2..]));
            let compressed = fs::read(object_path).expect("XTF object");
            let expected = format!("b3:{hash}").parse().expect("content hash");
            verify_compressed_segment(&compressed, expected).expect("verified XTF");
            return zstd::stream::decode_all(compressed.as_slice()).expect("decompress XTF");
        }
        assert!(Instant::now() < deadline, "request was not persisted to selected project");
        thread::sleep(Duration::from_millis(30));
    }
}

fn wait_for_recording_count(project_root: &Path, expected: i64) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let database = Connection::open(project_root.join("metadata.sqlite3")).expect("SQLite");
        let count: i64 = database
            .query_row("SELECT COUNT(*) FROM recordings", [], |row| row.get(0))
            .expect("recording count");
        if count >= expected {
            return;
        }
        assert!(Instant::now() < deadline, "expected {expected} persisted recordings, got {count}");
        thread::sleep(Duration::from_millis(30));
    }
}

fn recording_list_page(repo: &Path, data_home: &Path, after: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtrace"));
    command.args(["recording", "list", "--project-dir"]).arg(repo).args(["--limit", "1"]);
    if let Some(cursor) = after {
        command.args(["--after", cursor]);
    }
    command.env("XTRACE_DATA_HOME", data_home);
    command.output().expect("run xtrace recording list")
}

fn recording_show_page(
    repo: &Path,
    data_home: &Path,
    recording_id: &str,
    limit: u32,
    cursor: Option<&str>,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtrace"));
    command
        .args(["recording", "show", "--project-dir"])
        .arg(repo)
        .arg(recording_id)
        .args(["--limit", &limit.to_string()]);
    if let Some(cursor) = cursor {
        command.args(["--cursor", cursor]);
    }
    command.env("XTRACE_DATA_HOME", data_home);
    command.output().expect("run xtrace recording show")
}

fn launch_viewer(repo: &Path, data_home: &Path) -> (Value, ViewerProcess) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["open", "--project-dir"])
        .arg(repo)
        .args(["--viewer", "--no-browser"])
        .env("XTRACE_DATA_HOME", data_home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start foreground viewer");
    let stdout = child.stdout.take().expect("viewer stdout");
    let stderr = child.stderr.take().expect("viewer stderr");
    let stderr = thread::spawn(move || drain(stderr));
    let mut line = String::new();
    std::io::BufReader::new(stdout).read_line(&mut line).expect("read viewer readiness");
    let readiness: Value = serde_json::from_str(&line).expect("structured viewer readiness");
    assert_eq!(readiness["browserLaunch"], "not_requested");
    assert!(readiness["url"].as_str().is_some_and(|url| url.starts_with("http://127.0.0.1:")));
    (readiness, ViewerProcess { child, stderr: Some(stderr) })
}

fn assert_canaries_absent(bytes: &[u8]) {
    for canary in
        ["BODY_CANARY_1D4", "AUTH_CANARY_1D4", "COOKIE_CANARY_1D4", "PATH_QUERY_CANARY_1E2"]
    {
        assert!(
            !bytes.windows(canary.len()).any(|window| window == canary.as_bytes()),
            "{canary} leaked"
        );
    }
}

fn diagnostic(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[cfg(unix)]
fn file_state(path: &Path) -> (Vec<u8>, std::time::SystemTime, u32) {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = fs::metadata(path).expect("file metadata");
    (
        fs::read(path).expect("file bytes"),
        metadata.modified().expect("file mtime"),
        metadata.permissions().mode(),
    )
}

fn drain(mut reader: impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = reader.read_to_end(&mut bytes);
    bytes
}
