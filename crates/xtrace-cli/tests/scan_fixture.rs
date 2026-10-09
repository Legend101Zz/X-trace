//! `xtrace scan` journeys against a fake analyzer (a shell script that prints a transcript), so the
//! CLI plumbing is exercised without a JDK or Node. Real analyzers have their own suites.
#![cfg(unix)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unreachable,
    reason = "integration tests assert on fixed fixtures and checked subprocess output"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn write_analyzer(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("analyzer.sh");
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write analyzer");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod analyzer");
    path
}

const TRANSCRIPT: &str = r#"cat <<'EOF'
{"type":"header","contractVersion":1,"analyzerName":"fake","analyzerVersion":"0.0.1","rulesetId":"fake/1","framework":"express"}
{"type":"claim","method":"GET","routeParts":["/api","/users/:id"],"routeBasis":"literal","handler":"show","limitations":[],"evidence":{"path":"app.js","startLine":2,"startColumn":1,"endLine":2,"endColumn":30}}
{"type":"claim","method":"POST","routeParts":["/api/users"],"routeBasis":"computed","limitations":["route_constant_unresolved"],"evidence":{"path":"app.js","startLine":3,"startColumn":1,"endLine":3,"endColumn":30}}
{"type":"end","claims":2,"filesScanned":1,"complete":true,"incompleteReasons":[]}
EOF"#;

struct Project {
    dir: tempfile::TempDir,
}

impl Project {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::create_dir(dir.path().join("src")).expect("src dir");
        fs::write(dir.path().join("src/app.js"), "app.get('/api/users/:id', show);\n")
            .expect("source");
        Self { dir }
    }

    fn scan(&self, analyzer: &Path, source: &Path, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["scan", "--project-dir"])
            .arg(self.dir.path())
            .arg("--source")
            .arg(source)
            .args(["--framework", "express", "--analyzer"])
            .arg(analyzer)
            .args(extra)
            .arg("--json")
            .output()
            .expect("run xtrace scan")
    }
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("stdout is JSON")
}

#[test]
fn scan_fixture_prints_provenance_static_inferred_and_is_honestly_partial() {
    let project = Project::new();
    let analyzer = write_analyzer(project.dir.path(), TRANSCRIPT);
    let output = project.scan(&analyzer, &project.dir.path().join("src"), &[]);
    assert_eq!(output.status.code(), Some(10), "{output:?}");
    let document = json(&output);
    assert_eq!(document["status"], "not_persisted");
    assert_eq!(document["persisted"], false);
    assert!(document["catalogRevisionId"].is_null());
    assert_eq!(document["packStatus"], "dev_unsigned");
    assert_eq!(document["pathHypotheses"], "not_produced");
    let coverage = document["coverage"].as_str().expect("coverage statement");
    assert!(coverage.contains("receiver") && coverage.contains("unresolved"), "{coverage}");
    let result = &document["result"];
    assert_eq!(result["completion"], "complete");
    assert_eq!(result["claimCount"], 2);
    let operations = result["operations"].as_array().expect("operations");
    assert_eq!(operations.len(), 2);
    for operation in operations {
        assert_eq!(operation["provenance"], "static_inferred");
    }
    let get = operations.iter().find(|o| o["method"] == "GET").expect("GET operation");
    assert_eq!(get["routeTemplate"], "/api/users/{id}");
    assert_eq!(get["confidenceBasisPoints"], 9000);
    let post = operations.iter().find(|o| o["method"] == "POST").expect("POST operation");
    assert_eq!(post["confidenceBasisPoints"], 3000);
    assert_eq!(
        post["limitationCodes"],
        serde_json::json!(["route_computed", "route_constant_unresolved"])
    );
}

#[test]
fn scan_json_output_matches_schema() {
    let project = Project::new();
    let analyzer = write_analyzer(project.dir.path(), TRANSCRIPT);
    let document = json(&project.scan(&analyzer, &project.dir.path().join("src"), &[]));
    let mut keys: Vec<&str> =
        document.as_object().expect("object").keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "catalogRevisionId",
            "changes",
            "coverage",
            "notPersistedBecause",
            "packStatus",
            "parentRevisionId",
            "pathHypotheses",
            "persisted",
            "reconciliation",
            "result",
            "revisionOrdinal",
            "runId",
            "status"
        ]
    );
    let mut result_keys: Vec<&str> =
        document["result"].as_object().expect("result").keys().map(String::as_str).collect();
    result_keys.sort_unstable();
    assert_eq!(
        result_keys,
        [
            "analyzer",
            "claimCount",
            "completion",
            "diagnostics",
            "filesScanned",
            "framework",
            "incompleteReasons",
            "limitationHistogram",
            "operations",
            "rejectedClaims",
            "rulesetId"
        ]
    );
}

#[test]
fn scan_refuses_outside_project_dir() {
    let project = Project::new();
    let analyzer = write_analyzer(project.dir.path(), TRANSCRIPT);
    let elsewhere = tempfile::tempdir().expect("other dir");
    let output = project.scan(&analyzer, elsewhere.path(), &[]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "nothing is printed as a result");
    assert!(String::from_utf8_lossy(&output.stderr).contains("inside the project directory"));
}

#[test]
fn scan_incomplete_when_analyzer_times_out() {
    let project = Project::new();
    let analyzer = write_analyzer(project.dir.path(), "exec sleep 30");
    let output = project.scan(&analyzer, &project.dir.path().join("src"), &["--timeout-secs", "1"]);
    assert_eq!(output.status.code(), Some(10), "{output:?}");
    let result = &json(&output)["result"];
    assert_eq!(result["completion"], "incomplete");
    assert_eq!(result["incompleteReasons"], serde_json::json!(["analyzer_timeout"]));
    assert_eq!(result["claimCount"], 0);
}

#[test]
fn scan_times_out_an_analyzer_that_closes_stdout_and_keeps_running() {
    let project = Project::new();
    let analyzer = write_analyzer(project.dir.path(), "exec 1>&-\nexec sleep 30");
    let started = std::time::Instant::now();
    let output = project.scan(&analyzer, &project.dir.path().join("src"), &["--timeout-secs", "1"]);
    assert!(started.elapsed() < std::time::Duration::from_secs(20), "scan hung on child.wait");
    assert_eq!(output.status.code(), Some(10), "{output:?}");
    let result = &json(&output)["result"];
    assert_eq!(result["incompleteReasons"], serde_json::json!(["analyzer_timeout"]));
}

/// Alive means running: a zombie (terminated, not yet reaped) is gone. Under a child subreaper
/// (the release floor runner) orphans of killed children linger as zombies until it reaps them.
fn alive(pid: &str) -> bool {
    let Ok(output) = Command::new("ps").args(["-o", "stat=", "-p", pid]).output() else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let stat = String::from_utf8_lossy(&output.stdout);
    let stat = stat.trim_start();
    !stat.is_empty() && !stat.starts_with('Z')
}

#[test]
fn scan_timeout_stops_the_whole_process_group_of_a_forking_wrapper() {
    // Readiness handshake: the first exec of a freshly written script (and of `sleep`) can take
    // over a second on macOS. The wrapper has a warm-up mode that execs both and exits; running
    // it once before the scan pays that one-off cost outside the scan's timeout clock. The scan
    // itself then runs with the normal 1 s deadline and the grandchild (30 s) is stopped by it.
    let project = Project::new();
    let pid_file = project.dir.path().join("grandchild.pid");
    let body = format!(
        "if [ -n \"$XTRACE_TEST_WARMUP\" ]; then sleep 0; exit 0; fi\nsleep 30 &\necho $! > '{}'\nwait",
        pid_file.display()
    );
    let analyzer = write_analyzer(project.dir.path(), &body);
    let warmup = Command::new(&analyzer).env("XTRACE_TEST_WARMUP", "1").status().expect("warm up");
    assert!(warmup.success(), "analyzer warm-up failed");
    assert!(!pid_file.exists(), "warm-up must not start the grandchild");
    let output = project.scan(&analyzer, &project.dir.path().join("src"), &["--timeout-secs", "1"]);
    assert_eq!(output.status.code(), Some(10), "{output:?}");
    let pid = fs::read_to_string(&pid_file).expect("grandchild pid recorded");
    let pid = pid.trim();
    let mut gone = false;
    for _ in 0..50 {
        if !alive(pid) {
            gone = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(gone, "the forked grandchild {pid} survived the scan timeout");
}

#[test]
fn scan_rejects_jaxrs_until_an_analyzer_exists() {
    let project = Project::new();
    let analyzer = write_analyzer(project.dir.path(), TRANSCRIPT);
    let output = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["scan", "--project-dir"])
        .arg(project.dir.path())
        .arg("--source")
        .arg(project.dir.path().join("src"))
        .args(["--framework", "jaxrs", "--analyzer"])
        .arg(&analyzer)
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

#[test]
fn scan_marks_a_truncated_transcript_incomplete() {
    let project = Project::new();
    let body = TRANSCRIPT.replace("{\"type\":\"end\",\"claims\":2,\"filesScanned\":1,\"complete\":true,\"incompleteReasons\":[]}\n", "");
    let analyzer = write_analyzer(project.dir.path(), &body);
    let output = project.scan(&analyzer, &project.dir.path().join("src"), &[]);
    let result = &json(&output)["result"];
    assert_eq!(result["completion"], "incomplete");
    assert_eq!(result["incompleteReasons"], serde_json::json!(["transcript_truncated"]));
    assert_eq!(result["claimCount"], 2);
}

#[test]
fn scan_requires_an_analyzer_and_a_known_framework() {
    let project = Project::new();
    let output = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["scan", "--project-dir"])
        .arg(project.dir.path())
        .arg("--source")
        .arg(project.dir.path().join("src"))
        .args(["--framework", "express"])
        .env_remove("XTRACE_NODE_ANALYZER")
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
    let analyzer = write_analyzer(project.dir.path(), TRANSCRIPT);
    let output = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["scan", "--project-dir"])
        .arg(project.dir.path())
        .arg("--source")
        .arg(project.dir.path().join("src"))
        .args(["--framework", "rails", "--analyzer"])
        .arg(&analyzer)
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
}
