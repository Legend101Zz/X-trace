//! `xtrace record` accepts and resolves the same capture inputs as `xtrace run` (CONTRACTS 11.2)
//! and writes the resolved scope to the private `capture.json` that arms the daemon session.

#![cfg(unix)]
#![allow(missing_docs, reason = "integration test symbols are executable fixtures")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "end-to-end test asserts on controlled local process and fixture state"
)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;
use tempfile::TempDir;

struct Fixture {
    _root: TempDir,
    repo: PathBuf,
    data_home: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // The product's own identity-checked stop; never a raw signal. Already stopped is fine.
        let _ = Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["stop", "--project-dir"])
            .arg(&self.repo)
            .env("XTRACE_DATA_HOME", &self.data_home)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn fixture() -> Fixture {
    let base = std::env::temp_dir().canonicalize().expect("canonical temp base");
    let root = tempfile::Builder::new()
        .prefix("xt-recscope-")
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir_in(base)
        .expect("temporary root");
    let repo = root.path().join("repo");
    let data_home = root.path().join("data");
    std::fs::create_dir_all(&repo).expect("repo");
    let init = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["init", "--project-dir"])
        .arg(&repo)
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("init");
    assert!(init.status.success(), "init: {}", String::from_utf8_lossy(&init.stderr));
    Fixture { _root: root, repo, data_home }
}

impl Fixture {
    fn record(&self, flags: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .arg("record")
            .arg("--project-dir")
            .arg(&self.repo)
            .args(flags)
            .env("XTRACE_DATA_HOME", &self.data_home)
            .stdin(Stdio::null())
            .output()
            .expect("run xtrace record")
    }
}

fn capture_json_beside(document: &Value) -> Value {
    let bootstrap = Path::new(document["bootstrap_path"].as_str().expect("bootstrap path"));
    let capture = bootstrap.parent().expect("session directory").join("capture.json");
    let mode = std::fs::metadata(&capture).expect("capture.json exists").permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "capture.json is private");
    serde_json::from_slice(&std::fs::read(&capture).expect("read capture.json"))
        .expect("capture.json is JSON")
}

#[test]
fn record_writes_the_resolved_scope_and_reports_what_it_enforces() {
    let fx = fixture();
    let out = fx.record(&[
        "--capture-depth",
        "focused",
        "--app-package",
        "com.example.app",
        "--app-package",
        "com.example.app",
        "--source-root",
        "src/main/java",
    ]);
    assert!(out.status.success(), "record: {}", String::from_utf8_lossy(&out.stderr));
    let document: Value = serde_json::from_slice(&out.stdout).expect("record JSON");
    assert_eq!(document["capture_depth"], "focused");
    assert_eq!(
        document["capture_depth_enforced"], true,
        "the daemon's own reader arms the recorded depth from the private file"
    );
    assert_eq!(document["application_packages"], serde_json::json!(["com.example.app"]));
    assert_eq!(document["source_roots"], serde_json::json!(["src/main/java"]));

    let capture = capture_json_beside(&document);
    assert_eq!(capture["capture"]["mode"], "focused");
    assert_eq!(
        capture["application_scope"]["application_packages"],
        serde_json::json!(["com.example.app"]),
        "the duplicate prefix is resolved away exactly as `xtrace run` does"
    );
    assert_eq!(capture["application_scope"]["source_roots"], serde_json::json!(["src/main/java"]));
}

#[test]
fn record_without_scope_flags_writes_an_honestly_empty_standard_scope() {
    let fx = fixture();
    let out = fx.record(&[]);
    assert!(out.status.success(), "record: {}", String::from_utf8_lossy(&out.stderr));
    let document: Value = serde_json::from_slice(&out.stdout).expect("record JSON");
    assert_eq!(document["capture_depth"], "standard");
    assert_eq!(document["capture_depth_enforced"], true);
    assert_eq!(document["application_packages"], serde_json::json!([]));
    let capture = capture_json_beside(&document);
    assert_eq!(capture["capture"]["mode"], "standard");
    assert_eq!(capture["application_scope"]["application_packages"], serde_json::json!([]));
}

#[test]
fn record_rejects_the_capture_inputs_run_rejects_before_starting_a_daemon() {
    let fx = fixture();
    for bad in [
        &["--capture-depth", "deep"][..],
        &["--app-package", "not a package"][..],
        &["--app-package", "java.util"][..],
        &["--source-root", "../escape"][..],
        &["--launcher", "maven"][..],
    ] {
        let out = fx.record(bad);
        assert_eq!(out.status.code(), Some(2), "{bad:?} must be an argument error");
    }
    let state = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["stop", "--project-dir"])
        .arg(&fx.repo)
        .env("XTRACE_DATA_HOME", &fx.data_home)
        .output()
        .expect("stop");
    assert_eq!(state.status.code(), Some(3), "no daemon was started by a rejected record");
}
