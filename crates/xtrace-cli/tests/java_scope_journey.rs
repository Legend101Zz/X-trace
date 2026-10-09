//! Java launch journeys that need the Spring fixture: scope that matches nothing persists no
//! recording (stated positively, not read from absent frames), non-direct launchers are refused
//! before any side effect, and an operator-selected observation policy needs a resolved application scope.

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

struct OutOfScope {
    recording_count: usize,
    list_succeeded: bool,
    exit_code: Option<i32>,
    stderr: String,
}

/// An explicit `--app-package` that matches no class makes the Spring handler out of scope. The
/// agent's contract (`SpringMvcBridge.start`) is then: no request root, therefore no recording. This
/// journey states that outcome positively instead of reading "no frames" out of an absent
/// recording: the fixture served the request, the run shut down cleanly after the daemon
/// finalized, the store opened and listed successfully, and it holds zero recordings.
#[test]
fn out_of_scope_app_package_serves_the_request_and_persists_no_recording() {
    // Differential control: the same fixture, request and shutdown with a matching scope must
    // persist exactly one recording, so the zero below cannot come from a broken capture path.
    let control = run_out_of_scope(&["--app-package", "dev.xtrace.fixture"]);
    assert!(control.list_succeeded, "control store must open and list; stderr: {}", control.stderr);
    assert_eq!(
        control.recording_count, 1,
        "the in-scope control must record the one POST /orders; stderr: {}",
        control.stderr
    );
    let outcome = run_out_of_scope(&["--app-package", "com.nonexistent.app"]);
    assert!(outcome.list_succeeded, "the store must open and list; stderr: {}", outcome.stderr);
    assert_eq!(
        outcome.recording_count, 0,
        "an out-of-scope handler must open no request root, so no recording; stderr: {}",
        outcome.stderr
    );
    assert!(
        !outcome.stderr.contains("capture_incomplete"),
        "a deliberate scope exclusion is not an incomplete capture: {}",
        outcome.stderr
    );
    assert!(
        matches!(outcome.exit_code, Some(0 | 143)),
        "the run must end by the forwarded shutdown signal: {:?}",
        outcome.exit_code
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

fn run_out_of_scope(flags: &[&str]) -> OutOfScope {
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
    // The request has been served; let the agent and daemon finish, then shut down cleanly.
    thread::sleep(Duration::from_secs(3));
    let pid = rustix::process::Pid::from_raw(process.child.id() as i32).expect("CLI process ID");
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).expect("signal xtrace run");
    let status = process.child.wait().expect("wait for signal shutdown");
    let _ = process.stdout.take().expect("stdout thread").join();
    let stderr = process.stderr.take().expect("stderr thread").join().expect("join stderr");

    let list = cli(&["recording", "list"], &repo, &data_home);
    let parsed = serde_json::from_slice::<Value>(&list.stdout).ok();
    let recording_count = parsed
        .as_ref()
        .and_then(|value| value["recordings"].as_array().map(Vec::len))
        .unwrap_or(usize::MAX);
    OutOfScope {
        recording_count,
        list_succeeded: list.status.success() && parsed.is_some(),
        exit_code: status.code(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    }
}

fn cli(args: &[&str], repo: &Path, data_home: &Path) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtrace"));
    command.arg(args[0]).arg(args[1]).arg("--project-dir").arg(repo).args(&args[2..]);
    command.env("XTRACE_DATA_HOME", data_home).output().expect("run xtrace")
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
