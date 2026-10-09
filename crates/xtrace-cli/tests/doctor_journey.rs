//! Real-process checks for `xtrace doctor`: healthy project, injected faults, honest unavailable items.

#![cfg(unix)]
#![allow(missing_docs, reason = "integration test symbols are executable fixtures")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "end-to-end test asserts on controlled local process and fixture state"
)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::Value;
use tempfile::TempDir;

struct Fx {
    _root: TempDir,
    repo: PathBuf,
    data_home: PathBuf,
    project_id: String,
}

impl Drop for Fx {
    fn drop(&mut self) {
        // Identity-checked product stop; a no-op (ignored error) when nothing is running.
        let _ = Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["stop", "--project-dir"])
            .arg(&self.repo)
            .env("XTRACE_DATA_HOME", &self.data_home)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn fx() -> Fx {
    let base = std::env::temp_dir().canonicalize().expect("canonical temp base");
    let root = tempfile::Builder::new()
        .prefix("xt-doc-")
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
    let doc: Value = serde_json::from_slice(&init.stdout).expect("init JSON");
    let project_id = doc["project_id"].as_str().expect("project_id").to_string();
    Fx { _root: root, repo, data_home, project_id }
}

impl Fx {
    fn xtrace(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(args)
            .arg("--project-dir")
            .arg(&self.repo)
            .env("XTRACE_DATA_HOME", &self.data_home)
            .stdin(Stdio::null())
            .output()
            .expect("run xtrace")
    }
}

fn status_of(report: &Value, id: &str) -> String {
    report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["id"] == id)
        .unwrap_or_else(|| panic!("check {id} missing from {report}"))["status"]
        .as_str()
        .expect("status")
        .to_string()
}

#[test]
fn healthy_project_reports_ok_and_honest_unavailable_items() {
    let fx = fx();
    let out = fx.xtrace(&["doctor"]);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let report: Value = serde_json::from_slice(&out.stdout).expect("report JSON");
    assert_eq!(report["kind"], "doctor_report");
    assert_eq!(report["version"], "0.0.1");
    assert_eq!(status_of(&report, "binary"), "ok");
    assert_eq!(status_of(&report, "private_storage"), "ok");
    assert_eq!(status_of(&report, "store_schema"), "ok");
    assert_eq!(status_of(&report, "daemon_lock"), "ok");
    assert_eq!(status_of(&report, "recordings"), "ok");
    // Not performed in this build: must say so rather than pass.
    assert_eq!(status_of(&report, "store_integrity"), "unavailable");
    assert_eq!(
        status_of(&report, "pack_java"),
        "unavailable",
        "a build tree has no installed packs"
    );
    assert!(report["summary"]["unavailable"].as_u64().unwrap() >= 3);
    assert_ne!(report["overall"], "fail");
}

#[test]
fn world_readable_project_root_is_reported_as_a_failure_with_nonzero_exit() {
    let fx = fx();
    let root = fx.data_home.join("projects").join(&fx.project_id);
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).expect("chmod fault");
    let out = fx.xtrace(&["doctor"]);
    let report: Value = serde_json::from_slice(&out.stdout).expect("report JSON");
    assert_eq!(report["overall"], "fail", "{report}");
    assert_eq!(status_of(&report, "project"), "fail");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn a_live_daemon_is_reported_and_bundle_is_refused_not_ignored() {
    let fx = fx();
    let started = fx.xtrace(&["record"]);
    assert!(started.status.success(), "{}", String::from_utf8_lossy(&started.stderr));
    let report: Value = {
        let out = fx.xtrace(&["doctor"]);
        assert_eq!(out.status.code(), Some(0));
        serde_json::from_slice(&out.stdout).expect("report JSON")
    };
    let lock = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "daemon_lock")
        .unwrap();
    assert!(lock["detail"].as_str().unwrap().starts_with("a process holds"), "{lock}");
    let bundle = fx.xtrace(&["doctor", "--bundle", "/nonexistent/never-written.zip"]);
    assert_eq!(bundle.status.code(), Some(9));
    assert!(!std::path::Path::new("/nonexistent/never-written.zip").exists());
    let stopped = fx.xtrace(&["stop"]);
    assert!(stopped.status.success(), "{}", String::from_utf8_lossy(&stopped.stderr));
}

#[test]
fn a_store_with_an_older_schema_is_a_warning_not_a_failure() {
    let fx = fx();
    // Make the (otherwise healthy) store claim to be one migration behind this build.
    let database = std::fs::read_dir(fx.data_home.join("projects"))
        .expect("projects dir")
        .map(|entry| entry.expect("entry").path().join("metadata.sqlite3"))
        .find(|path| path.is_file())
        .expect("the initialized project's store");
    let connection = rusqlite::Connection::open(&database).expect("open store file");
    let changed = connection
        .execute(
            "UPDATE schema_meta SET schema_version = schema_version - 1 WHERE singleton = 1",
            [],
        )
        .expect("lower the recorded schema version");
    assert_eq!(changed, 1);
    drop(connection);
    let out = fx.xtrace(&["doctor"]);
    let report: Value = serde_json::from_slice(&out.stdout).expect("report JSON");
    assert_eq!(status_of(&report, "store_schema"), "warn", "{report}");
    assert_eq!(out.status.code(), Some(0), "a pending migration is not a failure: {report}");
}
