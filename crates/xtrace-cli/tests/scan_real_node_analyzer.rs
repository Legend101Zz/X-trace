//! `xtrace scan` driving the REAL Node static analyzer (no canned transcript) over the
//! `express-basic` fixture, then reading the persisted catalog back.
//!
//! The analyzer is the one built by the npm workspace (`npm run build --prefix adapters/node`,
//! which CI runs before the Rust tests). A thin shell wrapper only supplies the `node` launcher
//! because `xtrace scan --analyzer` executes a path directly; every byte of the transcript comes
//! from the live analyzer reading the fixture sources.  A missing build is a hard failure, never a skip.
#![cfg(unix)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests assert on fixed fixtures and checked subprocess output"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create dir");
    for entry in fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy file");
        }
    }
}

struct StopOnDrop {
    repo: PathBuf,
    data_home: PathBuf,
}

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        let _ = Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["stop", "--project-dir"])
            .arg(&self.repo)
            .env("XTRACE_DATA_HOME", &self.data_home)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("stdout is JSON ({e}): {output:?}"))
}

#[test]
fn real_node_analyzer_scan_persists_the_express_basic_catalog() {
    let main_js = repo_root().join("adapters/node/packages/analyzer/dist/main.js");
    assert!(
        main_js.is_file(),
        "build the Node analyzer first: npm run build --prefix adapters/node ({})",
        main_js.display()
    );

    let base = std::env::temp_dir().canonicalize().expect("canonical temp base");
    let root = tempfile::Builder::new()
        .prefix("xt-real-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(base)
        .expect("temporary root");
    let repo = root.path().join("repo");
    let data_home = root.path().join("data");
    let _stop = StopOnDrop { repo: repo.clone(), data_home: data_home.clone() };
    fs::create_dir_all(&repo).expect("repo");
    let xtrace = |args: &[&str]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(args)
            .arg("--project-dir")
            .arg(&repo)
            .env("XTRACE_DATA_HOME", &data_home)
            .stdin(Stdio::null())
            .output()
            .expect("run xtrace")
    };
    let init = xtrace(&["init"]);
    assert!(init.status.success(), "init: {}", String::from_utf8_lossy(&init.stderr));

    copy_tree(
        &repo_root().join("adapters/node/packages/analyzer/test-fixtures/express-basic"),
        &repo.join("src"),
    );
    let wrapper = root.path().join("node-analyzer.sh");
    fs::write(&wrapper, format!("#!/bin/sh\nexec node '{}' \"$@\"\n", main_js.display()))
        .expect("wrapper");
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).expect("chmod");

    let source = repo.join("src");
    let scan = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["scan", "--project-dir"])
        .arg(&repo)
        .arg("--source")
        .arg(&source)
        .args(["--framework", "express", "--application-component", "express-basic", "--analyzer"])
        .arg(&wrapper)
        .arg("--json")
        .env("XTRACE_DATA_HOME", &data_home)
        .stdin(Stdio::null())
        .output()
        .expect("run xtrace scan");
    assert_eq!(scan.status.code(), Some(0), "{scan:?}");
    let doc = json(&scan);
    assert_eq!(doc["status"], "persisted_complete");
    assert_eq!(doc["result"]["completion"], "complete");
    assert_eq!(doc["revisionOrdinal"], 1);

    // The live analyzer must agree with its committed golden output on how many mappings exist.
    let golden = fs::read_to_string(
        repo_root().join("adapters/node/packages/analyzer/golden/express-basic.transcript.jsonl"),
    )
    .expect("golden");
    let golden_claims = golden.lines().filter(|l| l.contains("\"type\":\"claim\"")).count();
    let operations = doc["result"]["operations"].as_array().expect("operations").len();
    assert!(operations >= 10, "{operations}");
    assert_eq!(operations, golden_claims);

    let list = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["catalog", "list", "--project-dir"])
        .arg(&repo)
        .arg("--json")
        .env("XTRACE_DATA_HOME", &data_home)
        .stdin(Stdio::null())
        .output()
        .expect("run xtrace catalog list");
    assert!(list.status.success(), "{list:?}");
    let list = json(&list);
    let ops = list["operations"].as_array().expect("operations");
    assert_eq!(ops.len(), operations);
    let find = |method: &str, route: &str| -> &Value {
        ops.iter()
            .find(|op| op["method"] == method && op["routeTemplate"] == route)
            .unwrap_or_else(|| panic!("{method} {route} missing from {list}"))
    };
    let show = find("GET", "/api/users/{id}");
    assert_eq!(show["provenance"], serde_json::json!(["static_inferred"]));
    assert_eq!(show["sourcePath"], "routes/users.js");
    assert_eq!(show["handlers"], serde_json::json!(["show"]));
    let lonely = find("GET", "/lonely");
    assert!(lonely["limitationCodes"].as_array().unwrap().contains(&"mount_unresolved".into()));
}
