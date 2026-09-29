//! Subprocess acceptance checks for the foreground daemon CLI lifecycle.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "subprocess fixtures use fixed local paths and checked assertions"
)]

use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;

fn temp_root(label: &str) -> TempDir {
    let base = std::env::temp_dir().canonicalize().expect("canonical temp base");
    tempfile::Builder::new().prefix(label).tempdir_in(base).expect("temporary root")
}

fn initialize(repo: &Path, data_home: &Path) {
    std::fs::create_dir_all(repo).expect("repository directory");
    let output = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["init", "--project-dir"])
        .arg(repo)
        .env("XTRACE_DATA_HOME", data_home)
        .output()
        .expect("run init");
    assert!(output.status.success(), "init stderr: {}", String::from_utf8_lossy(&output.stderr));
}

fn start_daemon(
    repo: &Path,
    data_home: &Path,
) -> (Child, BufReader<std::process::ChildStdout>, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["daemon", "--project-dir"])
        .arg(repo)
        .env("XTRACE_DATA_HOME", data_home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon");
    let stdout = child.stdout.take().expect("piped stdout");
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let reader_task = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line);
        let _ = sender.send((reader, line, result));
    });
    let (reader, line, result) = match receiver.recv_timeout(Duration::from_secs(10)) {
        Ok(value) => value,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader_task.join();
            panic!("daemon readiness timed out or reader failed: {error}");
        }
    };
    if let Err(error) = result {
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader_task.join();
        panic!("read daemon readiness: {error}");
    }
    let ready: Value = match serde_json::from_str(&line) {
        Ok(value) => value,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("readiness JSON: {error}; line={line:?}");
        }
    };
    (child, reader, ready)
}

fn signal_and_wait(child: &mut Child, signal: &str) {
    let pid = child.id().to_string();
    let status = Command::new("kill").args([signal, &pid]).status().expect("send process signal");
    assert!(status.success(), "signal command failed");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().expect("poll daemon").is_some() {
            break;
        }
        assert!(Instant::now() < deadline, "daemon did not stop after {signal}");
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn force_kill(child: &mut Child) {
    let pid = child.id().to_string();
    let status = Command::new("kill").args(["-KILL", &pid]).status().expect("send SIGKILL");
    assert!(status.success());
    assert!(!child.wait().expect("wait killed daemon").success());
}

#[cfg(unix)]
#[test]
fn readiness_is_single_safe_json_lock_is_exclusive_and_sigint_cleans_artifacts() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = temp_root("xtrace-cli-daemon-e2e-");
    let repo = root.path().join("repository with spaces");
    let data_home = root.path().join("data home");
    initialize(&repo, &data_home);

    let (mut child, mut reader, ready) = start_daemon(&repo, &data_home);
    assert_eq!(ready["kind"], "daemon_bound");
    assert_eq!(ready["recording_ingress"], "durable_segments");
    assert_eq!(ready["ack_durability"], "staged");
    assert_eq!(ready["capture_supported"], false);
    assert_eq!(ready["replay_supported"], false);
    let bootstrap_path = PathBuf::from(ready["bootstrap_path"].as_str().expect("bootstrap path"));
    let session_dir = bootstrap_path.parent().expect("session directory").to_path_buf();
    let bootstrap = std::fs::read_to_string(&bootstrap_path).expect("bootstrap exists");
    let session_secret =
        serde_json::from_str::<Value>(&bootstrap).expect("bootstrap JSON")["session_secret_base64"]
            .as_str()
            .expect("bootstrap secret")
            .to_string();
    assert!(!serde_json::to_string(&ready).expect("serialize readiness").contains(&session_secret));
    assert_eq!(
        std::fs::metadata(&session_dir).expect("session dir").permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&bootstrap_path).expect("bootstrap").permissions().mode() & 0o777,
        0o600
    );

    let contention = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["daemon", "--project-dir"])
        .arg(&repo)
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("run contending daemon");
    assert!(!contention.status.success());
    let error: Value = serde_json::from_slice(&contention.stderr).expect("contention JSON");
    assert_eq!(error["code"], "XTR-CLI-DAEMON-LOCKED");

    signal_and_wait(&mut child, "-INT");
    let mut extra = String::new();
    assert_eq!(reader.read_line(&mut extra).expect("read trailing stdout"), 0);
    assert!(!session_dir.exists(), "runtime artifacts cleaned after shutdown");
    let stderr = child.stderr.take().expect("piped stderr");
    let stderr = std::io::read_to_string(stderr).expect("read stderr");
    assert!(!stderr.contains(&session_secret));
    assert!(child.wait().expect("wait daemon").success());
}

#[cfg(unix)]
#[test]
fn sigterm_also_releases_project_lock_for_a_later_start() {
    let root = temp_root("xtrace-cli-daemon-sigterm-");
    let repo = root.path().join("repo");
    let data_home = root.path().join("data");
    initialize(&repo, &data_home);
    let (mut child, _, _) = start_daemon(&repo, &data_home);
    signal_and_wait(&mut child, "-TERM");
    assert!(child.wait().expect("wait daemon").success());
    let (mut second, _, _) = start_daemon(&repo, &data_home);
    signal_and_wait(&mut second, "-INT");
    assert!(second.wait().expect("wait second daemon").success());
}

#[cfg(unix)]
#[test]
fn next_start_cleans_known_runtime_artifacts_left_by_sigkill() {
    let root = temp_root("xtrace-cli-daemon-sigkill-");
    let repo = root.path().join("repo");
    let data_home = root.path().join("data");
    initialize(&repo, &data_home);
    let (mut child, _, ready) = start_daemon(&repo, &data_home);
    let bootstrap_path = PathBuf::from(ready["bootstrap_path"].as_str().expect("bootstrap path"));
    let stale_session = bootstrap_path.parent().expect("session dir").to_path_buf();
    force_kill(&mut child);
    assert!(stale_session.exists(), "SIGKILL cannot run daemon cleanup");

    let (mut restarted, _, _) = start_daemon(&repo, &data_home);
    assert!(!stale_session.exists(), "next lock owner cleans known stale artifacts");
    signal_and_wait(&mut restarted, "-INT");
    assert!(restarted.wait().expect("wait restarted daemon").success());
}
