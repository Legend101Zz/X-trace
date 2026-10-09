//! Java launch journeys that need the Spring fixture: scope that matches nothing still persists a
//! recording (with zero application frames), non-direct launchers are refused before any side
//! effect, and an operator-selected observation policy needs a resolved application scope.

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
fn out_of_scope_app_package_persists_a_recording_with_zero_application_frames() {
    let captured = run_fixture(&["--app-package", "com.nonexistent.app"]);
    // A persisted recording is required: "no recording" and "a recording without application
    // frames" are different outcomes and only the second is what an out-of-scope launch means.
    assert!(
        !captured.detail_pages.is_empty(),
        "an out-of-scope launch must still persist a recording; stderr: {}",
        captured.stderr
    );
    let application_frames: Vec<&Value> = captured
        .events
        .iter()
        .filter(|event| {
            event["kind"].as_str().is_some_and(|kind| kind.ends_with("frame_enter"))
                && event["symbol"].as_str().is_some_and(|symbol| {
                    symbol.contains("Order") || symbol.contains("dev.xtrace.fixture")
                })
        })
        .collect();
    assert!(
        application_frames.is_empty(),
        "an app package that matches no class must not capture application frames: \
         {application_frames:?}"
    );
}

#[test]
fn non_direct_launchers_are_refused_with_a_clear_error_before_any_launch() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let agent =
        workspace.join("adapters/java/agent-bootstrap/build/agent-dist/xtrace-java-agent.jar");
    assert!(agent.is_file(), "Gradle agentDist must run before this test");
    // `--launcher gradle` is refused by the flag, a gradle/mvn/wrapper command by the direct-java
    // rule; both exit 2 and neither creates a project data directory.
    let cases: [(&[&str], &[&str], &str); 4] = [
        (&["--launcher", "gradle"], &["gradle", "bootRun"], "only executes `--launcher direct`"),
        (
            &["--launcher", "maven"],
            &["mvn", "spring-boot:run"],
            "only executes `--launcher direct`",
        ),
        (&[], &["./gradlew", "bootRun"], "only a direct executable named java"),
        (&[], &["mvn", "spring-boot:run"], "only a direct executable named java"),
    ];
    for (flags, command, expected) in cases {
        let root = temp_root();
        let repo = root.path().join("repository");
        let data_home = root.path().join("data home");
        fs::create_dir_all(&repo).expect("repository");
        let output = Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["run", "--project-dir"])
            .arg(&repo)
            .arg("--java-agent")
            .arg(&agent)
            .args(flags)
            .arg("--")
            .args(command)
            .env("XTRACE_DATA_HOME", &data_home)
            .output()
            .expect("run xtrace");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{flags:?} {command:?}: {stderr}");
        assert!(stderr.contains(expected), "{flags:?} {command:?}: {stderr}");
        assert!(!data_home.exists(), "{flags:?} {command:?}: refusal must create no project data");
    }
}

#[test]
fn observation_policy_requires_a_resolved_application_scope() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let agent =
        workspace.join("adapters/java/agent-bootstrap/build/agent-dist/xtrace-java-agent.jar");
    assert!(agent.is_file(), "Gradle agentDist must run before this test");
    let root = temp_root();
    let repo = root.path().join("repository");
    let data_home = root.path().join("data home");
    fs::create_dir_all(&repo).expect("repository");
    // No --app-package and no Spring Boot fat jar: scope is empty, so the policy is refused
    // before the JVM starts or any daemon is prepared.
    let output = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["run", "--project-dir"])
        .arg(&repo)
        .arg("--java-agent")
        .arg(&agent)
        .args([
            "--observed-endpoint-policy",
            "spring-orders-v1",
            "--application-component",
            "spring-fixture",
            "--binding-key",
            "default",
        ])
        .args(["--", "java", "-version"])
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("run xtrace");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("needs a resolved application scope"), "{stderr}");
    assert!(!data_home.exists(), "refusal must create no project data");
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
