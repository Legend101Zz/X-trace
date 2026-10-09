//! `xtrace scan` persisting catalog revisions, and `xtrace catalog ...` reading them back, through
//! the real binary against a real initialized project.
//!
//! The analyzer is a shell script that prints a committed transcript, so no JDK or Node build is
//! needed. The Express transcript is the committed golden output of the real Node analyzer for
//! the `express-basic` fixture (the Node suite asserts byte equality against the live analyzer).
//! The Spring transcript is scripted by hand against the real `spring-fixture` sources: no Java
//! golden exists yet, so this test proves the scan/catalog plumbing and the runtime reconciliation,
//! not the Java analyzer.
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
use tempfile::TempDir;

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

struct Fx {
    _root: TempDir,
    repo: PathBuf,
    data_home: PathBuf,
    project_id: String,
}

impl Drop for Fx {
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

fn fx() -> Fx {
    let base = std::env::temp_dir().canonicalize().expect("canonical temp base");
    let root = tempfile::Builder::new()
        .prefix("xt-scan-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(base)
        .expect("temporary root");
    let repo = root.path().join("repo");
    let data_home = root.path().join("data");
    fs::create_dir_all(&repo).expect("repo");
    let init = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["init", "--project-dir"])
        .arg(&repo)
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("init");
    assert!(init.status.success(), "init: {}", String::from_utf8_lossy(&init.stderr));
    let doc: Value = serde_json::from_slice(&init.stdout).expect("init JSON");
    let project_id = doc["project_id"].as_str().expect("project_id").to_owned();
    Fx { _root: root, repo, data_home, project_id }
}

impl Fx {
    fn write_analyzer(&self, transcript: &str) -> PathBuf {
        fs::write(self.repo.join("transcript.jsonl"), transcript).expect("transcript");
        let path = self.repo.join("analyzer.sh");
        fs::write(&path, "#!/bin/sh\ncat \"$(dirname \"$0\")/transcript.jsonl\"\n")
            .expect("analyzer");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    fn scan(&self, framework: &str, component: &str, analyzer: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["scan", "--project-dir"])
            .arg(&self.repo)
            .arg("--source")
            .arg(self.repo.join("src"))
            .args(["--framework", framework, "--application-component", component, "--analyzer"])
            .arg(analyzer)
            .arg("--json")
            .env("XTRACE_DATA_HOME", &self.data_home)
            .stdin(Stdio::null())
            .output()
            .expect("run xtrace scan")
    }

    fn catalog(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .arg("catalog")
            .args(args)
            .arg("--project-dir")
            .arg(&self.repo)
            .arg("--json")
            .env("XTRACE_DATA_HOME", &self.data_home)
            .stdin(Stdio::null())
            .output()
            .expect("run xtrace catalog")
    }

    fn database(&self) -> PathBuf {
        self.data_home.join("projects").join(&self.project_id).join("metadata.sqlite3")
    }
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("stdout is JSON ({e}): {output:?}"))
}

fn operation<'a>(list: &'a Value, method: &str, route: &str) -> &'a Value {
    list["operations"]
        .as_array()
        .expect("operations")
        .iter()
        .find(|op| op["method"] == method && op["routeTemplate"] == route)
        .unwrap_or_else(|| panic!("{method} {route} missing from {list}"))
}

fn golden(name: &str) -> String {
    fs::read_to_string(repo_root().join("adapters/node/packages/analyzer/golden").join(name))
        .expect("golden transcript")
}

fn express_fx() -> (Fx, String) {
    let fx = fx();
    copy_tree(
        &repo_root().join("adapters/node/packages/analyzer/test-fixtures/express-basic"),
        &fx.repo.join("src"),
    );
    let transcript = golden("express-basic.transcript.jsonl");
    (fx, transcript)
}

/// Rewrites the golden transcript: drops `/v2/status`, renames the handler of `GET /api/users/`,
/// adds one new mapping, and keeps the end line's claim count truthful.
fn edited_express_transcript(golden: &str) -> String {
    let mut lines: Vec<Value> =
        golden.lines().map(|l| serde_json::from_str(l).expect("line")).collect();
    lines.retain(|l| l["routeParts"] != serde_json::json!(["/v2", "/status"]));
    for line in &mut lines {
        if line["routeParts"] == serde_json::json!(["/api/users", "/"]) {
            line["handler"] = Value::from("listAll");
        }
    }
    let end = lines.len() - 1;
    lines.insert(
        end,
        serde_json::json!({"type":"claim","method":"POST","routeParts":["/api/users","/:id/archive"],
            "routeBasis":"concatenated","handler":"archive","limitations":[],
            "evidence":{"path":"routes/users.js","startLine":7,"startColumn":1,"endLine":7,"endColumn":26}}),
    );
    let claims = lines.iter().filter(|l| l["type"] == "claim").count();
    let last = lines.len() - 1;
    lines[last]["claims"] = Value::from(claims);
    lines.iter().map(|l| format!("{l}\n")).collect()
}

#[test]
fn express_fixture_scan_persists_an_immutable_revision_and_rescans_diff() {
    let (fx, transcript) = express_fx();
    let analyzer = fx.write_analyzer(&transcript);

    // First scan: complete, persisted, exit 0, a first revision with no parent.
    let first = fx.scan("express", "express-basic", &analyzer);
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    let first_doc = json(&first);
    assert_eq!(first_doc["status"], "persisted_complete");
    assert_eq!(first_doc["persisted"], true);
    assert_eq!(first_doc["result"]["completion"], "complete");
    assert_eq!(first_doc["packStatus"], "dev_unsigned");
    assert_eq!(first_doc["revisionOrdinal"], 1);
    assert!(first_doc["parentRevisionId"].is_null());
    let revision_one = first_doc["catalogRevisionId"].as_str().expect("revision id").to_owned();
    let operations = first_doc["result"]["operations"].as_array().expect("ops").len();
    assert!(operations >= 10, "{operations}");
    assert_eq!(first_doc["changes"]["added"], operations);

    // The catalog reads the same revision back, with static provenance and claim evidence.
    let list = json(&fx.catalog(&["list"]));
    assert_eq!(list["revision"]["revisionId"], revision_one.as_str());
    assert_eq!(list["operations"].as_array().unwrap().len(), operations);
    let show = operation(&list, "GET", "/api/users/{id}");
    assert_eq!(show["changeKind"], "added");
    assert_eq!(show["provenance"], serde_json::json!(["static_inferred"]));
    assert_eq!(show["sourcePath"], "routes/users.js");
    assert_eq!(show["sourceAvailability"], "unverified");
    assert_eq!(show["handlers"], serde_json::json!(["show"]));
    // An unresolved mount stays visibly weak, never an unqualified fact.
    let lonely = operation(&list, "GET", "/lonely");
    assert!(lonely["limitationCodes"].as_array().unwrap().contains(&"mount_unresolved".into()));

    // Same source, same claims: a second immutable revision, every entry unchanged.
    let second = json(&fx.scan("express", "express-basic", &analyzer));
    assert_eq!(second["status"], "persisted_complete");
    assert_eq!(second["revisionOrdinal"], 2);
    assert_eq!(second["parentRevisionId"], revision_one.as_str());
    assert_eq!(second["changes"]["unchanged"], operations);
    assert_eq!(second["changes"]["added"], 0);
    let revision_two = second["catalogRevisionId"].as_str().expect("revision id").to_owned();
    assert_ne!(revision_one, revision_two);

    // History is newest first and revision one is untouched.
    let history = json(&fx.catalog(&["history"]));
    let ids: Vec<&str> = history["revisions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["revisionId"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [revision_two.as_str(), revision_one.as_str()]);
    let again = json(&fx.catalog(&["list", "--revision", &revision_one]));
    assert_eq!(again["operations"], list["operations"], "revision one is immutable");

    // Changed claims: one handler renamed, one mapping new, one mapping not seen again.
    let edited = fx.write_analyzer(&edited_express_transcript(&transcript));
    let third = json(&fx.scan("express", "express-basic", &edited));
    assert_eq!(third["status"], "persisted_complete");
    assert_eq!(third["revisionOrdinal"], 3);
    assert_eq!(third["changes"]["added"], 1);
    assert_eq!(third["changes"]["changed"], 1);
    assert_eq!(third["changes"]["unknown"], 1);
    let diff = json(&fx.catalog(&["diff"]));
    assert_eq!(diff["counts"]["added"], 1);
    assert_eq!(diff["counts"]["changed"], 1);
    assert_eq!(diff["counts"]["unknown"], 1);
    assert!(diff["counts"].get("removed").is_none(), "absence is never removal: {diff}");
    let entries = diff["entries"].as_array().unwrap();
    let labelled = |route: &str| {
        entries.iter().find(|e| e["routeTemplate"] == route).map(|e| e["change"].clone())
    };
    assert_eq!(labelled("/v2/status"), Some("unknown".into()));
    assert_eq!(labelled("/api/users/{id}/archive"), Some("added".into()));
    assert_eq!(labelled("/api/users"), Some("changed".into()));

    // The explicit pair form agrees with the default (parent -> newest).
    let pair = json(&fx.catalog(&[
        "diff",
        "--from",
        &revision_two,
        "--to",
        third["catalogRevisionId"].as_str().unwrap(),
    ]));
    assert_eq!(pair["counts"], diff["counts"]);
}

#[test]
fn incomplete_scan_records_a_run_but_never_a_revision_and_removes_nothing() {
    let (fx, transcript) = express_fx();
    let analyzer = fx.write_analyzer(&transcript);
    let complete = json(&fx.scan("express", "express-basic", &analyzer));
    assert_eq!(complete["status"], "persisted_complete");

    // The same claims, but the analyzer admits it could not parse everything.
    let incomplete: String = transcript
        .lines()
        .map(|line| {
            if line.contains("\"type\":\"end\"") {
                r#"{"type":"end","claims":15,"filesScanned":6,"complete":false,"incompleteReasons":["unsupported_syntax"]}"#
                    .to_owned()
            } else {
                line.to_owned()
            }
        })
        .map(|line| format!("{line}\n"))
        .collect();
    let partial_analyzer = fx.write_analyzer(&incomplete);
    let partial = fx.scan("express", "express-basic", &partial_analyzer);
    assert_eq!(partial.status.code(), Some(10), "{partial:?}");
    let partial_doc = json(&partial);
    assert_eq!(partial_doc["status"], "incomplete_recorded");
    assert_eq!(partial_doc["persisted"], false);
    assert!(partial_doc["catalogRevisionId"].is_null());
    assert_eq!(partial_doc["result"]["completion"], "incomplete");
    assert!(
        partial_doc["result"]["incompleteReasons"]
            .as_array()
            .unwrap()
            .contains(&"unsupported_syntax".into())
    );

    // History still has exactly the complete revision; the run list shows both runs honestly.
    let history = json(&fx.catalog(&["history"]));
    assert_eq!(history["revisions"].as_array().unwrap().len(), 1);
    let runs = json(&fx.catalog(&["runs"]));
    let statuses: Vec<&str> =
        runs["runs"].as_array().unwrap().iter().map(|r| r["status"].as_str().unwrap()).collect();
    assert_eq!(statuses, ["incomplete", "complete"]);
    // Nothing in the newest revision was marked removed.
    let list = json(&fx.catalog(&["list"]));
    assert!(list["operations"].as_array().unwrap().iter().all(|op| op["changeKind"] != "removed"));
}

#[test]
fn a_first_scan_with_an_incomplete_transcript_leaves_the_history_empty() {
    let (fx, transcript) = express_fx();
    let truncated: String = transcript
        .lines()
        .filter(|line| !line.contains("\"type\":\"end\""))
        .map(|line| format!("{line}\n"))
        .collect();
    let analyzer = fx.write_analyzer(&truncated);
    let output = fx.scan("express", "express-basic", &analyzer);
    assert_eq!(output.status.code(), Some(10), "{output:?}");
    assert_eq!(json(&output)["status"], "incomplete_recorded");
    let history = json(&fx.catalog(&["history"]));
    assert_eq!(history["revisions"], serde_json::json!([]));
    let list = fx.catalog(&["list"]);
    assert_eq!(list.status.code(), Some(2), "no revision yet is a usage error: {list:?}");
}

/// Scripted Spring MVC transcript for the real `spring-fixture` sources.
const SPRING_TRANSCRIPT: &str = r#"{"type":"header","contractVersion":1,"analyzerName":"scripted-spring","analyzerVersion":"0.0.1","rulesetId":"spring-mvc-scripted/1","framework":"spring-mvc"}
{"type":"claim","method":"POST","routeParts":["/orders"],"routeBasis":"literal","handler":"OrderController.create","limitations":[],"evidence":{"path":"OrderController.java","startLine":23,"startColumn":3,"endLine":24,"endColumn":86}}
{"type":"claim","method":"GET","routeParts":["/__fixture","/count"],"routeBasis":"concatenated","handler":"FixtureAdminController.count","limitations":[],"evidence":{"path":"FixtureAdminController.java","startLine":20,"startColumn":3,"endLine":21,"endColumn":40}}
{"type":"claim","method":"GET","routeParts":["/__fixture","/isolation"],"routeBasis":"concatenated","handler":"FixtureAdminController.isolation","limitations":[],"evidence":{"path":"FixtureAdminController.java","startLine":26,"startColumn":3,"endLine":27,"endColumn":43}}
{"type":"end","claims":3,"filesScanned":2,"complete":true,"incompleteReasons":[]}
"#;

/// Records one `POST /orders` observation exactly as a run of the Spring fixture would, through
/// the store's public recording API.
fn record_orders_observation(fx: &Fx) {
    use xtrace_application::recording::EndpointObservationInput;
    use xtrace_domain::{ProjectId, RecordingId, RuntimeSessionId, WallTime};
    use xtrace_store::{
        BeginRecordingDisposition, BeginRecordingRequest, OpenOptions, SqliteStore,
    };

    let database = fx.database();
    let root = database.parent().expect("project data root").to_path_buf();
    let store = SqliteStore::open(&database, OpenOptions::default().with_must_exist(true))
        .expect("open project store");
    let view = store.recording_store(&root).expect("recording view");
    let project_id = ProjectId::from_uuid(uuid::Uuid::parse_str(&fx.project_id).expect("uuid"));
    let receipt = view
        .begin_recording(&BeginRecordingRequest {
            project_id,
            recording_id: RecordingId::new(),
            runtime_session_id: RuntimeSessionId::new(),
            opened_at: WallTime::now(),
            endpoint_observation: EndpointObservationInput {
                policy_id: Some("spring-orders-v1".to_owned()),
                application_component: Some("spring-fixture".to_owned()),
                binding_key: Some("default".to_owned()),
                method: "POST".to_owned(),
                route_template: "/orders".to_owned(),
            },
        })
        .expect("begin recording");
    assert_eq!(receipt.disposition, BeginRecordingDisposition::Inserted);
}

#[test]
fn spring_fixture_scan_reconciles_static_claims_with_an_observed_recording() {
    let fx = fx();
    let sources = repo_root().join("adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture");
    fs::create_dir_all(fx.repo.join("src")).expect("src");
    for file in ["OrderController.java", "FixtureAdminController.java"] {
        fs::copy(sources.join(file), fx.repo.join("src").join(file)).expect("copy source");
    }
    let analyzer = fx.write_analyzer(SPRING_TRANSCRIPT);

    // A recording of POST /orders exists before the scan (record-first), then the scan runs.
    record_orders_observation(&fx);
    let scan = fx.scan("spring-mvc", "spring-fixture", &analyzer);
    assert_eq!(scan.status.code(), Some(0), "{scan:?}");
    let doc = json(&scan);
    assert_eq!(doc["status"], "persisted_complete");
    assert_eq!(doc["changes"]["added"], 3);

    // The scan itself reports how its claims fare against what was observed.
    assert_eq!(doc["reconciliation"]["confirmed"], 1);
    assert_eq!(doc["reconciliation"]["unobserved"], 2);
    assert_eq!(doc["reconciliation"]["undeclared"], 0);

    let reconcile = json(&fx.catalog(&["reconcile"]));
    assert_eq!(reconcile["confirmed"], 1);
    let rows = reconcile["reconciliation"]["rows"].as_array().expect("rows");
    let orders = rows.iter().find(|r| r["routeTemplate"] == "/orders").expect("orders row");
    assert_eq!(orders["status"], "confirmed");
    assert_eq!(orders["recordingCount"], 1);
    for route in ["/__fixture/count", "/__fixture/isolation"] {
        let row = rows.iter().find(|r| r["routeTemplate"] == route).expect("fixture row");
        assert_eq!(row["status"], "static_only", "{route}");
    }

    // The catalog operation for POST /orders is the very operation the recording linked to.
    let list = json(&fx.catalog(&["list"]));
    let orders_op = operation(&list, "POST", "/orders");
    let connection = rusqlite::Connection::open(fx.database()).expect("sqlite");
    let linked: String = connection
        .query_row(
            "SELECT lower(hex(operation_id)) FROM operations WHERE method = 'POST' AND route_template = '/orders'",
            [],
            |row| row.get(0),
        )
        .expect("recorded operation");
    let catalog_id = orders_op["operationId"].as_str().expect("operation id").replace('-', "");
    assert_eq!(catalog_id, linked, "scan reuses the identity the recording created");
}

#[test]
fn catalog_reconcile_reports_an_endpoint_observed_but_not_declared() {
    let fx = fx();
    let sources = repo_root().join("adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture");
    fs::create_dir_all(fx.repo.join("src")).expect("src");
    fs::copy(
        sources.join("FixtureAdminController.java"),
        fx.repo.join("src/FixtureAdminController.java"),
    )
    .expect("copy source");
    // The scan only declares the admin endpoints; POST /orders is recorded but never declared.
    let transcript = SPRING_TRANSCRIPT
        .lines()
        .filter(|line| !line.contains("OrderController"))
        .map(|line| {
            if line.contains("\"type\":\"end\"") {
                r#"{"type":"end","claims":2,"filesScanned":1,"complete":true,"incompleteReasons":[]}"#
                    .to_owned()
            } else {
                line.to_owned()
            }
        })
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let analyzer = fx.write_analyzer(&transcript);
    record_orders_observation(&fx);
    let scan = json(&fx.scan("spring-mvc", "spring-fixture", &analyzer));
    assert_eq!(scan["status"], "persisted_complete");
    assert_eq!(scan["reconciliation"]["undeclared"], 1);
    assert_eq!(scan["reconciliation"]["confirmed"], 0);
    let reconcile = json(&fx.catalog(&["reconcile"]));
    let row = reconcile["reconciliation"]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["routeTemplate"] == "/orders")
        .expect("orders row");
    assert_eq!(row["status"], "observed_only");
}

#[test]
fn scan_in_an_uninitialized_project_still_analyzes_and_says_why_it_did_not_persist() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::create_dir(dir.path().join("src")).expect("src");
    fs::write(dir.path().join("src/app.js"), "x\n").expect("source");
    let analyzer = dir.path().join("analyzer.sh");
    fs::write(&analyzer, "#!/bin/sh\ncat <<'EOF'\n{\"type\":\"header\",\"contractVersion\":1,\"analyzerName\":\"f\",\"analyzerVersion\":\"1\",\"rulesetId\":\"r/1\",\"framework\":\"express\"}\n{\"type\":\"claim\",\"method\":\"GET\",\"routeParts\":[\"/a\"],\"routeBasis\":\"literal\",\"limitations\":[],\"evidence\":{\"path\":\"app.js\",\"startLine\":1,\"startColumn\":1,\"endLine\":1,\"endColumn\":2}}\n{\"type\":\"end\",\"claims\":1,\"filesScanned\":1,\"complete\":true,\"incompleteReasons\":[]}\nEOF\n").expect("analyzer");
    fs::set_permissions(&analyzer, fs::Permissions::from_mode(0o755)).expect("chmod");
    let output = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["scan", "--project-dir"])
        .arg(dir.path())
        .arg("--source")
        .arg(dir.path().join("src"))
        .args(["--framework", "express", "--analyzer"])
        .arg(&analyzer)
        .arg("--json")
        .output()
        .expect("scan");
    assert_eq!(output.status.code(), Some(10), "{output:?}");
    let doc = json(&output);
    assert_eq!(doc["status"], "not_persisted");
    assert_eq!(doc["persisted"], false);
    assert!(doc["notPersistedBecause"].as_str().unwrap().contains("xtrace init"));
    assert_eq!(doc["result"]["operations"].as_array().unwrap().len(), 1);
}
