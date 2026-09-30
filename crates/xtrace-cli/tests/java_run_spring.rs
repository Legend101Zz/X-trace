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
use xtrace_application::recording::{
    BeginRecording, EndpointObservationInput, RecordingPersistencePort,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{OperationId, ProjectId, RecordingId, RuntimeSessionId, WallTime};
use xtrace_store::verify_compressed_segment;
use xtrace_store::{OpenOptions, SqliteRecordingPersistence, SqliteStore};

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
    let project_root = data_home.join("projects").join(&project_id);

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
        .args([
            "--observed-endpoint-policy",
            "spring-orders-v1",
            "--application-component",
            "spring-fixture",
            "--binding-key",
            "default",
        ])
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
    let database = Connection::open(project_root.join("metadata.sqlite3")).expect("SQLite");
    let operation_count: i64 = database
        .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
        .expect("operation count");
    let linked_count: i64 = database
        .query_row(
            "SELECT COUNT(*) FROM recording_endpoint_observations WHERE disposition = 'linked' AND observation_policy_id = 'spring-orders-v1' AND application_component = 'spring-fixture' AND binding_key = 'default' AND method = 'POST' AND route_template = '/orders'",
            [],
            |row| row.get(0),
        )
        .expect("linked observations");
    assert_eq!(operation_count, 1);
    assert_eq!(linked_count, 2);
    let recording_ids = database
        .prepare("SELECT recording_id FROM recordings")
        .expect("prepare recording identity query")
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("query recording identities")
        .collect::<Result<Vec<_>, _>>()
        .expect("read recording identities");
    assert_eq!(recording_ids.len(), 2);
    for bytes in recording_ids {
        assert_eq!(bytes.len(), 16, "recording UUID width");
        assert_eq!(bytes[6] >> 4, 7, "future Spring captures use UUIDv7");
        assert_eq!(bytes[8] >> 6, 2, "recording UUID retains the RFC variant");
    }

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
    let pointer = repo.join(".xtrace/config.toml");
    let database_before_endpoint_queries = fs::read(&database).expect("database snapshot");
    let pointer_before_endpoint_queries = file_state(&pointer);
    let objects_before_endpoint_queries = object_files_state(&project_root.join("objects/b3"));
    let query_operation = endpoint_list_page(&repo, &data_home, None, None);
    assert!(
        query_operation.status.success(),
        "endpoint list failed: {}",
        diagnostic(&query_operation)
    );
    let endpoint_json: Value =
        serde_json::from_slice(&query_operation.stdout).expect("endpoint page");
    assert_eq!(endpoint_json["items"].as_array().expect("items").len(), 1);
    assert_eq!(endpoint_json["items"][0]["method"], "POST");
    assert_eq!(endpoint_json["items"][0]["routeTemplate"], "/orders");
    assert_eq!(endpoint_json["items"][0]["observation"], "observed");
    assert_eq!(endpoint_json["items"][0]["observationPolicy"], "spring-orders-v1");
    let operation_id =
        endpoint_json["items"][0]["operationId"].as_str().expect("operation ID").to_owned();
    assert!(endpoint_json["nextCursor"].is_null(), "finite policy has one endpoint");
    assert_canaries_absent(&query_operation.stdout);

    let before_endpoint_cursor = endpoint_cursor(
        &project_id,
        OperationId::from_uuid(uuid::Uuid::from_bytes([
            0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0,
        ])),
    );
    let before_endpoint =
        endpoint_list_page(&repo, &data_home, Some(&before_endpoint_cursor), None);
    assert!(before_endpoint.status.success(), "valid endpoint cursor failed");
    let before_json: Value = serde_json::from_slice(&before_endpoint.stdout).expect("before page");
    assert_eq!(before_json["items"].as_array().expect("before items").len(), 1);
    let after_endpoint_cursor = endpoint_cursor(
        &project_id,
        OperationId::from_uuid(uuid::Uuid::from_bytes([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ])),
    );
    let after_endpoint = endpoint_list_page(&repo, &data_home, Some(&after_endpoint_cursor), None);
    assert!(after_endpoint.status.success(), "valid terminal endpoint cursor failed");
    let after_json: Value = serde_json::from_slice(&after_endpoint.stdout).expect("after page");
    assert!(after_json["items"].as_array().expect("after items").is_empty());
    assert!(after_json["nextCursor"].is_null());
    assert_eq!(
        fs::read(&database).expect("database after endpoint reads"),
        database_before_endpoint_queries
    );
    assert_eq!(file_state(&pointer), pointer_before_endpoint_queries);

    let database = project_root.join("metadata.sqlite3");
    let database_before_legacy_queries = fs::read(&database).expect("database snapshot");
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
    assert_eq!(
        fs::read(&database).expect("database after legacy reads"),
        database_before_legacy_queries
    );

    let mut genuine_linked_ids = Vec::new();
    let mut genuine_cursor = None;
    for page_index in 0..3 {
        let output = endpoint_recordings_page(
            &repo,
            &data_home,
            &operation_id,
            1,
            genuine_cursor.as_deref(),
        );
        assert!(output.status.success(), "captured linked page failed: {}", diagnostic(&output));
        let page: Value = serde_json::from_slice(&output.stdout).expect("captured linked page");
        for item in page["items"].as_array().expect("captured linked items") {
            assert_eq!(item["operationId"], operation_id);
            genuine_linked_ids
                .push(item["recordingId"].as_str().expect("captured recording ID").to_owned());
        }
        genuine_cursor = page["nextCursor"].as_str().map(str::to_owned);
        if genuine_cursor.is_none() {
            break;
        }
        assert!(page_index < 2, "captured linked cursor did not terminate");
    }
    assert_eq!(genuine_linked_ids.len(), 2, "both captured Spring recordings are linked");
    assert_eq!(
        genuine_linked_ids.iter().collect::<std::collections::HashSet<_>>().len(),
        genuine_linked_ids.len(),
        "captured Spring continuation has no duplicate recordings"
    );

    // Add bounded query fixtures only after selecting the real Spring recording for detail/browser checks.
    let (tie_ids, _unmatched_id, _legacy_id) =
        add_endpoint_cli_fixture_recordings(&project_root, &project_id);
    let database_before_queries = fs::read(&database).expect("database after query fixture setup");
    let pointer_before_query_fixtures = file_state(&pointer);

    let mut linked_ids = Vec::new();
    let mut next_cursor = None;
    for page_index in 0..5 {
        let output =
            endpoint_recordings_page(&repo, &data_home, &operation_id, 1, next_cursor.as_deref());
        assert!(output.status.success(), "linked recording page failed: {}", diagnostic(&output));
        assert_canaries_absent(&output.stdout);
        let page: Value = serde_json::from_slice(&output.stdout).expect("linked page JSON");
        let items = page["items"].as_array().expect("linked items");
        for item in items {
            assert_eq!(item["operationId"], operation_id);
            linked_ids.push(item["recordingId"].as_str().expect("recording ID").to_owned());
        }
        next_cursor = page["nextCursor"].as_str().map(str::to_owned);
        if next_cursor.is_none() {
            break;
        }
        assert!(page_index < 4, "linked recording cursor did not terminate");
    }
    assert_eq!(linked_ids.len(), genuine_linked_ids.len() + 2);
    assert_eq!(linked_ids[0], tie_ids[1], "same-time recording IDs sort descending");
    assert_eq!(linked_ids[1], tie_ids[0], "same-time recording IDs sort descending");
    for recording_id in &genuine_linked_ids {
        assert!(
            linked_ids.contains(recording_id),
            "captured Spring recording {recording_id} is retained after synthetic fixtures"
        );
    }
    assert_eq!(linked_ids.iter().collect::<std::collections::HashSet<_>>().len(), linked_ids.len());

    let mut unmatched_ids = Vec::new();
    let mut unmatched_cursor = None;
    let mut unmatched_rows = Vec::new();
    for page_index in 0..3 {
        let output = unmatched_recording_page(&repo, &data_home, 1, unmatched_cursor.as_deref());
        assert!(output.status.success(), "unmatched page failed: {}", diagnostic(&output));
        assert_canaries_absent(&output.stdout);
        let page: Value = serde_json::from_slice(&output.stdout).expect("unmatched page JSON");
        let items = page["items"].as_array().expect("unmatched items");
        for item in items {
            unmatched_ids.push(item["recordingId"].as_str().expect("recording ID").to_owned());
            unmatched_rows.push(item.clone());
        }
        unmatched_cursor = page["nextCursor"].as_str().map(str::to_owned);
        if unmatched_cursor.is_none() {
            break;
        }
        assert!(page_index < 2, "unmatched recording cursor did not terminate");
    }
    assert_eq!(unmatched_ids.len(), 2);
    assert_eq!(unmatched_ids.iter().collect::<std::collections::HashSet<_>>().len(), 2);
    assert!(
        unmatched_rows.iter().any(|item| item["unmatchedReason"] == "observation_policy_missing")
    );
    assert!(
        unmatched_rows.iter().any(|item| item["unmatchedReason"].is_null()),
        "legacy row has no fabricated reason"
    );

    let invalid_cursor = endpoint_list_page(&repo, &data_home, Some("CURSOR_PRIVACY_CANARY"), None);
    assert!(!invalid_cursor.status.success());
    let cursor_error: Value =
        serde_json::from_slice(&invalid_cursor.stderr).expect("structured cursor error");
    assert_eq!(cursor_error["code"], "XTR-VALIDATION-ENDPOINT-CURSOR");
    assert!(cursor_error["details"]["correlation_id"].as_str().is_some());
    assert!(!String::from_utf8_lossy(&invalid_cursor.stderr).contains("CURSOR_PRIVACY_CANARY"));
    for canary in ["-CURSOR_PRIVACY_CANARY", "--CURSOR_PRIVACY_CANARY"] {
        let invalid = endpoint_list_page(&repo, &data_home, Some(canary), None);
        assert!(!invalid.status.success(), "leading-hyphen cursor unexpectedly succeeded");
        let error: Value = serde_json::from_slice(&invalid.stderr).expect("hyphen cursor error");
        assert_eq!(error["code"], "XTR-VALIDATION-ENDPOINT-CURSOR");
        assert!(error["details"]["correlation_id"].as_str().is_some());
        assert!(!String::from_utf8_lossy(&invalid.stderr).contains(canary));
    }
    for canary in ["-UNMATCHED_CURSOR_CANARY", "--UNMATCHED_CURSOR_CANARY"] {
        let invalid = unmatched_recording_page(&repo, &data_home, 1, Some(canary));
        assert!(
            !invalid.status.success(),
            "leading-hyphen unmatched cursor unexpectedly succeeded"
        );
        let error: Value =
            serde_json::from_slice(&invalid.stderr).expect("hyphen unmatched cursor error");
        assert_eq!(error["code"], "XTR-VALIDATION-ENDPOINT-CURSOR");
        assert!(error["details"]["correlation_id"].as_str().is_some());
        assert!(!String::from_utf8_lossy(&invalid.stderr).contains(canary));
    }

    let invalid_limit =
        endpoint_recordings_page(&repo, &data_home, &operation_id, "LIMIT_PRIVACY_CANARY", None);
    assert!(!invalid_limit.status.success());
    let limit_error: Value =
        serde_json::from_slice(&invalid_limit.stderr).expect("structured limit error");
    assert_eq!(limit_error["code"], "XTR-VALIDATION-ENDPOINT-QUERY");
    assert!(!String::from_utf8_lossy(&invalid_limit.stderr).contains("LIMIT_PRIVACY_CANARY"));
    for canary in ["-LIMIT_PRIVACY_CANARY", "--LIMIT_PRIVACY_CANARY"] {
        let invalid = endpoint_recordings_page(&repo, &data_home, &operation_id, canary, None);
        assert!(!invalid.status.success(), "leading-hyphen limit unexpectedly succeeded");
        let error: Value = serde_json::from_slice(&invalid.stderr).expect("hyphen limit error");
        assert_eq!(error["code"], "XTR-VALIDATION-ENDPOINT-QUERY");
        assert!(error["details"]["correlation_id"].as_str().is_some());
        assert!(!String::from_utf8_lossy(&invalid.stderr).contains(canary));
    }

    for limit in ["0", "101"] {
        let invalid = endpoint_list_page(&repo, &data_home, None, Some(limit));
        assert_eq!(invalid.status.code(), Some(2));
        let error: Value = serde_json::from_slice(&invalid.stderr).expect("endpoint limit error");
        assert_eq!(error["code"], "XTR-VALIDATION-ENDPOINT-QUERY");
    }
    let oversized_linked = endpoint_recordings_page(&repo, &data_home, &operation_id, 51, None);
    assert_eq!(oversized_linked.status.code(), Some(2));
    let oversized_unmatched = unmatched_recording_page(&repo, &data_home, 51, None);
    assert_eq!(oversized_unmatched.status.code(), Some(2));

    let malformed_operation =
        endpoint_recordings_page(&repo, &data_home, "OPERATION_PRIVACY_CANARY", 1, None);
    assert!(!malformed_operation.status.success());
    let operation_error: Value =
        serde_json::from_slice(&malformed_operation.stderr).expect("structured operation error");
    assert_eq!(operation_error["code"], "XTR-VALIDATION-ENDPOINT-QUERY");
    assert!(
        !String::from_utf8_lossy(&malformed_operation.stderr).contains("OPERATION_PRIVACY_CANARY")
    );
    for canary in ["-OPERATION_PRIVACY_CANARY", "--OPERATION_PRIVACY_CANARY"] {
        let invalid = endpoint_recordings_page(&repo, &data_home, canary, 1, None);
        assert!(!invalid.status.success(), "leading-hyphen operation ID unexpectedly succeeded");
        let error: Value = serde_json::from_slice(&invalid.stderr).expect("hyphen operation error");
        assert_eq!(error["code"], "XTR-VALIDATION-ENDPOINT-QUERY");
        assert!(error["details"]["correlation_id"].as_str().is_some());
        assert!(!String::from_utf8_lossy(&invalid.stderr).contains(canary));
    }

    for canary in ["-RECORDING_CURSOR_CANARY", "--RECORDING_CURSOR_CANARY"] {
        let invalid = recording_list_page(&repo, &data_home, Some(canary));
        assert!(!invalid.status.success(), "leading-hyphen legacy cursor unexpectedly succeeded");
        let error: Value =
            serde_json::from_slice(&invalid.stderr).expect("hyphen legacy cursor error");
        assert_eq!(error["code"], "XTR-VALIDATION-RECORDING-CURSOR");
        assert!(error["details"]["correlation_id"].as_str().is_some());
        assert!(!String::from_utf8_lossy(&invalid.stderr).contains(canary));
    }
    for canary in ["-SHOW_CURSOR_CANARY", "--SHOW_CURSOR_CANARY"] {
        let invalid = recording_show_page(&repo, &data_home, first_recording, 1, Some(canary));
        assert!(!invalid.status.success(), "leading-hyphen show cursor unexpectedly succeeded");
        let error: Value =
            serde_json::from_slice(&invalid.stderr).expect("hyphen show cursor error");
        assert_eq!(error["code"], "XTR-VALIDATION-RECORDING-CURSOR");
        assert!(error["details"]["correlation_id"].as_str().is_some());
        assert!(!String::from_utf8_lossy(&invalid.stderr).contains(canary));
    }

    let mut unknown_bytes = OperationId::new().as_uuid().into_bytes();
    unknown_bytes[6] = (unknown_bytes[6] & 0x0f) | 0x70;
    unknown_bytes[8] = (unknown_bytes[8] & 0x3f) | 0x80;
    let unknown_id = OperationId::from_uuid(uuid::Uuid::from_bytes(unknown_bytes)).to_string();
    let unknown = endpoint_recordings_page(&repo, &data_home, &unknown_id, 1, None);

    let other_repo = root.path().join("other repository");
    fs::create_dir_all(&other_repo).expect("other repository");
    let other_init = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["init", "--project-dir"])
        .arg(&other_repo)
        .env("XTRACE_DATA_HOME", root.path().join("other data"))
        .output()
        .expect("initialize isolated project");
    assert!(other_init.status.success());
    let other_data = root.path().join("other data");
    let empty_endpoints = endpoint_list_page(&other_repo, &other_data, None, None);
    assert!(empty_endpoints.status.success());
    let empty_page: Value =
        serde_json::from_slice(&empty_endpoints.stdout).expect("empty page JSON");
    assert!(empty_page["items"].as_array().expect("empty endpoint items").is_empty());
    assert!(empty_page["nextCursor"].is_null());
    let cross_project = endpoint_recordings_page(&other_repo, &other_data, &operation_id, 1, None);
    assert_eq!(safe_not_found_signature(&unknown), safe_not_found_signature(&cross_project));

    let main_project_cursor = endpoint_cursor(&project_id, OperationId::new());
    let cross_scope_cursor =
        endpoint_list_page(&other_repo, &other_data, Some(&main_project_cursor), None);
    assert!(!cross_scope_cursor.status.success());
    let scope_error: Value =
        serde_json::from_slice(&cross_scope_cursor.stderr).expect("scope cursor error");
    assert_eq!(scope_error["code"], "XTR-VALIDATION-ENDPOINT-CURSOR");
    assert!(!String::from_utf8_lossy(&cross_scope_cursor.stderr).contains(&main_project_cursor));

    let linked_first = endpoint_recordings_page(&repo, &data_home, &operation_id, 1, None);
    let linked_first_json: Value =
        serde_json::from_slice(&linked_first.stdout).expect("first linked page");
    let linked_cursor =
        linked_first_json["nextCursor"].as_str().expect("linked continuation cursor");
    let other_operation_id = unknown_id;
    let cross_operation_cursor =
        endpoint_recordings_page(&repo, &data_home, &other_operation_id, 1, Some(linked_cursor));
    assert!(!cross_operation_cursor.status.success());
    let operation_scope_error: Value =
        serde_json::from_slice(&cross_operation_cursor.stderr).expect("operation cursor error");
    assert_eq!(operation_scope_error["code"], "XTR-VALIDATION-ENDPOINT-CURSOR");

    let stale_cursor = endpoint_list_page(
        &repo,
        &data_home,
        Some(&endpoint_cursor_version(&project_id, OperationId::new(), 99)),
        None,
    );
    assert!(!stale_cursor.status.success());
    let stale_error: Value =
        serde_json::from_slice(&stale_cursor.stderr).expect("stale cursor error");
    assert_eq!(stale_error["code"], "XTR-VALIDATION-ENDPOINT-CURSOR");
    let noncanonical_cursor = endpoint_list_page(
        &repo,
        &data_home,
        Some(&noncanonical_endpoint_cursor(&project_id, OperationId::new())),
        None,
    );
    assert_eq!(noncanonical_cursor.status.code(), Some(2));
    let noncanonical_error: Value =
        serde_json::from_slice(&noncanonical_cursor.stderr).expect("noncanonical cursor error");
    assert_eq!(noncanonical_error["code"], "XTR-VALIDATION-ENDPOINT-CURSOR");

    let database_before_incompatible_queries = fs::read(&database).expect("database snapshot");
    let pointer_before_incompatible_queries = file_state(&pointer);
    let objects_before_incompatible_queries = object_files_state(&project_root.join("objects/b3"));
    let incompatible = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["recording", "list", "--project-dir"])
        .arg(&repo)
        .args(["--unmatched", "--after", "RECORDING_CURSOR_CANARY"])
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("reject incompatible cursor modes");
    assert!(!incompatible.status.success());
    assert!(
        String::from_utf8_lossy(&incompatible.stderr).contains("XTR-VALIDATION-ENDPOINT-QUERY")
    );
    assert!(!String::from_utf8_lossy(&incompatible.stderr).contains("RECORDING_CURSOR_CANARY"));
    for options in [
        ["--unmatched", "--after", "-AFTER_ORDER_CANARY", "--cursor", "-CURSOR_ORDER_CANARY"],
        ["--unmatched", "--cursor", "-CURSOR_ORDER_CANARY", "--after", "-AFTER_ORDER_CANARY"],
    ] {
        let missing_repo = root.path().join("missing repository for cursor conflict");
        let rejected = Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["recording", "list", "--project-dir"])
            .arg(missing_repo)
            .args(options)
            .env("XTRACE_DATA_HOME", &data_home)
            .output()
            .expect("reject cursor conflict before project resolution");
        assert!(!rejected.status.success());
        let error: Value =
            serde_json::from_slice(&rejected.stderr).expect("structured cursor conflict");
        assert_eq!(error["code"], "XTR-VALIDATION-ENDPOINT-QUERY");
        assert!(!String::from_utf8_lossy(&rejected.stderr).contains("AFTER_ORDER_CANARY"));
        assert!(!String::from_utf8_lossy(&rejected.stderr).contains("CURSOR_ORDER_CANARY"));
        assert!(!String::from_utf8_lossy(&rejected.stderr).contains("missing repository"));
    }
    let legacy_cursor_mode = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["recording", "list", "--project-dir"])
        .arg(&repo)
        .args(["--cursor", "RECORDING_CURSOR_CANARY"])
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("reject cursor without unmatched mode");
    assert!(!legacy_cursor_mode.status.success());
    assert!(
        !String::from_utf8_lossy(&legacy_cursor_mode.stderr).contains("RECORDING_CURSOR_CANARY")
    );
    assert_eq!(
        fs::read(&database).expect("database after incompatible queries"),
        database_before_incompatible_queries
    );
    assert_eq!(file_state(&pointer), pointer_before_incompatible_queries);
    assert_eq!(
        object_files_state(&project_root.join("objects/b3")),
        objects_before_incompatible_queries
    );

    assert_eq!(fs::read(&database).expect("database after read queries"), database_before_queries);
    assert_eq!(file_state(&pointer), pointer_before_query_fixtures);
    assert_eq!(
        object_files_state(&project_root.join("objects/b3")),
        objects_before_endpoint_queries
    );

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

fn endpoint_list_page(
    repo: &Path,
    data_home: &Path,
    cursor: Option<&str>,
    limit: Option<&str>,
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtrace"));
    command.args(["endpoint", "list", "--project-dir"]).arg(repo);
    if let Some(limit) = limit {
        command.args(["--limit", limit]);
    }
    if let Some(cursor) = cursor {
        command.args(["--cursor", cursor]);
    }
    command.env("XTRACE_DATA_HOME", data_home);
    command.output().expect("run xtrace endpoint list")
}

fn endpoint_recordings_page(
    repo: &Path,
    data_home: &Path,
    operation_id: &str,
    limit: impl ToString,
    cursor: Option<&str>,
) -> std::process::Output {
    let limit = limit.to_string();
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtrace"));
    command
        .args(["endpoint", "recordings", operation_id, "--project-dir"])
        .arg(repo)
        .args(["--limit", &limit]);
    if let Some(cursor) = cursor {
        command.args(["--cursor", cursor]);
    }
    command.env("XTRACE_DATA_HOME", data_home);
    command.output().expect("run xtrace endpoint recordings")
}

fn unmatched_recording_page(
    repo: &Path,
    data_home: &Path,
    limit: u32,
    cursor: Option<&str>,
) -> std::process::Output {
    let limit = limit.to_string();
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtrace"));
    command.args(["recording", "list", "--project-dir"]).arg(repo).args([
        "--unmatched",
        "--limit",
        &limit,
    ]);
    if let Some(cursor) = cursor {
        command.args(["--cursor", cursor]);
    }
    command.env("XTRACE_DATA_HOME", data_home);
    command.output().expect("run xtrace unmatched recording list")
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

#[derive(serde::Serialize)]
struct EndpointCursor<'a> {
    version: u32,
    kind: &'static str,
    project_id: &'a str,
    filter: &'static str,
    sort: &'static str,
    last: EndpointCursorKey,
}

#[derive(serde::Serialize)]
struct EndpointCursorKey {
    method: &'static str,
    route_template: &'static str,
    application_component: &'static str,
    binding: &'static str,
    operation_id: String,
}

fn endpoint_cursor(project_id: &str, operation_id: OperationId) -> String {
    endpoint_cursor_version(project_id, operation_id, 1)
}

fn endpoint_cursor_version(project_id: &str, operation_id: OperationId, version: u32) -> String {
    let value = EndpointCursor {
        version,
        kind: "endpoints",
        project_id,
        filter: "observed",
        sort: "method_route_component_binding_operation_id_asc",
        last: EndpointCursorKey {
            method: "POST",
            route_template: "/orders",
            application_component: "spring-fixture",
            binding: "default",
            operation_id: operation_id.to_string(),
        },
    };
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&value).expect("serialize canonical endpoint cursor"))
}

fn noncanonical_endpoint_cursor(project_id: &str, operation_id: OperationId) -> String {
    use base64::Engine as _;
    let canonical = endpoint_cursor(project_id, operation_id);
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(canonical)
        .expect("decode canonical cursor");
    let mut noncanonical = Vec::with_capacity(bytes.len() + 1);
    noncanonical.push(b' ');
    noncanonical.extend_from_slice(&bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(noncanonical)
}

fn object_files_state(root: &Path) -> Vec<(PathBuf, Vec<u8>, std::time::SystemTime, u32)> {
    fn collect(directory: &Path, state: &mut Vec<(PathBuf, Vec<u8>, std::time::SystemTime, u32)>) {
        for entry in fs::read_dir(directory).expect("object directory") {
            let entry = entry.expect("object entry");
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).expect("object metadata");
            assert!(!metadata.file_type().is_symlink(), "object path must not be a symlink");
            if metadata.is_dir() {
                collect(&path, state);
            } else {
                use std::os::unix::fs::PermissionsExt as _;
                state.push((
                    path.clone(),
                    fs::read(&path).expect("object bytes"),
                    metadata.modified().expect("object mtime"),
                    metadata.permissions().mode(),
                ));
            }
        }
    }

    let mut state = Vec::new();
    if root.exists() {
        collect(root, &mut state);
    }
    state.sort_by(|left, right| left.0.cmp(&right.0));
    state
}

fn safe_not_found_signature(output: &std::process::Output) -> (String, String, String) {
    assert!(!output.status.success());
    let value: Value = serde_json::from_slice(&output.stderr).expect("structured not-found error");
    (
        value["code"].as_str().expect("error code").to_owned(),
        value["category"].as_str().expect("error category").to_owned(),
        value["message"].as_str().expect("safe message").to_owned(),
    )
}

fn add_endpoint_cli_fixture_recordings(
    project_root: &Path,
    project_id: &str,
) -> ([String; 2], String, String) {
    let project_id = project_id.parse::<ProjectId>().expect("project ID");
    let database_path = project_root.join("metadata.sqlite3");
    let connection = Connection::open(&database_path).expect("open captured recording database");
    let latest_opened_at: Option<String> = connection
        .query_row("SELECT MAX(opened_at) FROM recordings", [], |row| row.get(0))
        .expect("read latest captured recording time");
    drop(connection);
    let latest_opened_at =
        latest_opened_at.expect("captured recordings exist before synthetic rows");
    let latest_opened_at = time::OffsetDateTime::parse(
        &latest_opened_at,
        &time::format_description::well_known::Rfc3339,
    )
    .expect("stored recording timestamp is RFC 3339");
    let tie_timestamp = latest_opened_at
        .checked_add(time::Duration::days(1))
        .expect("later synthetic fixture timestamp is representable")
        .format(&time::format_description::well_known::Rfc3339)
        .expect("synthetic fixture timestamp is RFC 3339");
    let opened_at = tie_timestamp.parse::<WallTime>().expect("synthetic WallTime");
    let store = SqliteStore::open(&database_path, OpenOptions::default().with_must_exist(true))
        .expect("open fixture recording store");
    let persistence = SqliteRecordingPersistence::new(store, project_root);
    let linked_observation = EndpointObservationInput {
        policy_id: Some("spring-orders-v1".to_owned()),
        application_component: Some("spring-fixture".to_owned()),
        binding_key: Some("default".to_owned()),
        method: "POST".to_owned(),
        route_template: "/orders".to_owned(),
    };
    let linked_ids = [
        // A fixed canonical v4 ID exercises the historical producer format.
        uuid::Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0001),
        // A fixed v7 ID ties by opened_at with the v4 row above.
        uuid::Uuid::from_u128(0x018f_0000_0000_7000_8000_0000_0000_0002),
    ];
    for raw_id in linked_ids {
        let recording_id = RecordingId::from_uuid(raw_id);
        persistence
            .begin_recording(&BeginRecording {
                project_id,
                recording_id,
                runtime_session_id: RuntimeSessionId::new(),
                opened_at,
                endpoint_observation: linked_observation.clone(),
            })
            .expect("create same-time linked recording");
    }
    let unmatched_id = RecordingId::new();
    persistence
        .begin_recording(&BeginRecording {
            project_id,
            recording_id: unmatched_id,
            runtime_session_id: RuntimeSessionId::new(),
            opened_at,
            endpoint_observation: EndpointObservationInput::default(),
        })
        .expect("create unmatched sidecar recording");
    // This sidecar-free row models a historical v4 recording without making
    // it tie with the linked fixture rows.
    let legacy_id =
        RecordingId::from_uuid(uuid::Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0002));
    let historical_opened_at =
        WallTime::from_parts(2024, 1, 2, 12, 0, 0, 0).expect("historical legacy timestamp");
    persistence
        .begin_recording(&BeginRecording {
            project_id,
            recording_id: legacy_id,
            runtime_session_id: RuntimeSessionId::new(),
            opened_at: historical_opened_at,
            endpoint_observation: EndpointObservationInput::default(),
        })
        .expect("create legacy precursor recording");
    let connection = Connection::open(project_root.join("metadata.sqlite3")).expect("SQLite");
    connection
        .execute(
            "DELETE FROM recording_endpoint_observations WHERE recording_id = ?1",
            [legacy_id.as_uuid().as_bytes().to_vec()],
        )
        .expect("remove sidecar to model a legacy recording");
    (
        [linked_ids[0].to_string(), linked_ids[1].to_string()],
        unmatched_id.to_string(),
        legacy_id.to_string(),
    )
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
