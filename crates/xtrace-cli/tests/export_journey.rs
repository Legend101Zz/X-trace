//! `xtrace export` through the real binary against a real initialized project: scan a scripted
//! Spring transcript (real catalog persistence), persist one recording through the store's public
//! API, then export every format and compare to the expected structure. The same helpers as
//! `scan_catalog_journey` are used; the analyzer is a shell script that prints a transcript.
#![cfg(unix)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests assert on fixed fixtures and checked subprocess output"
)]

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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
        .prefix("xt-export-")
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
        support::write_executable(&path, "#!/bin/sh\ncat \"$(dirname \"$0\")/transcript.jsonl\"\n");
        path
    }

    fn scan(&self, analyzer: &Path) -> Output {
        self.scan_scope(analyzer, "spring-fixture", "default")
    }

    fn scan_scope(&self, analyzer: &Path, component: &str, binding: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["scan", "--project-dir"])
            .arg(&self.repo)
            .arg("--source")
            .arg(self.repo.join("src"))
            .args([
                "--framework",
                "spring-mvc",
                "--application-component",
                component,
                "--binding-key",
                binding,
                "--analyzer",
            ])
            .arg(analyzer)
            .arg("--json")
            .env("XTRACE_DATA_HOME", &self.data_home)
            .stdin(Stdio::null())
            .output()
            .expect("run xtrace scan")
    }

    fn export(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .arg("export")
            .args(args)
            .arg("--project-dir")
            .arg(&self.repo)
            .arg("--json")
            .env("XTRACE_DATA_HOME", &self.data_home)
            .stdin(Stdio::null())
            .output()
            .expect("run xtrace export")
    }

    fn database(&self) -> PathBuf {
        self.data_home.join("projects").join(&self.project_id).join("metadata.sqlite3")
    }

    fn out_dir(&self, name: &str) -> PathBuf {
        self._root.path().join(name)
    }
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("stdout is JSON ({e}): {output:?}"))
}

const TRANSCRIPT: &str = r#"{"type":"header","contractVersion":1,"analyzerName":"scripted-spring","analyzerVersion":"0.0.1","rulesetId":"spring-mvc-scripted/1","framework":"spring-mvc"}
{"type":"claim","method":"POST","routeParts":["/orders"],"routeBasis":"literal","handler":"OrderController.create","limitations":[],"evidence":{"path":"OrderController.java","startLine":23,"startColumn":3,"endLine":24,"endColumn":86}}
{"type":"claim","method":"GET","routeParts":["/orders","/{id}"],"routeBasis":"concatenated","handler":"OrderController.get","limitations":[],"evidence":{"path":"OrderController.java","startLine":30,"startColumn":3,"endLine":31,"endColumn":40}}
{"type":"claim","method":"GET","routeParts":["/__fixture","/count"],"routeBasis":"concatenated","handler":"FixtureAdminController.count","limitations":[],"evidence":{"path":"FixtureAdminController.java","startLine":20,"startColumn":3,"endLine":21,"endColumn":40}}
{"type":"end","claims":3,"filesScanned":2,"complete":true,"incompleteReasons":[]}
"#;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

fn project_with_catalog(transcript: &str) -> Fx {
    let fx = fx();
    let sources = repo_root().join("adapters/java/spring-fixture/src/main/java/dev/xtrace/fixture");
    fs::create_dir_all(fx.repo.join("src")).expect("src");
    for file in ["OrderController.java", "FixtureAdminController.java"] {
        fs::copy(sources.join(file), fx.repo.join("src").join(file)).expect("copy source");
    }
    let analyzer = fx.write_analyzer(transcript);
    record_orders_observation(&fx);
    let scan = fx.scan(&analyzer);
    assert_eq!(scan.status.code(), Some(0), "{scan:?}");
    fx
}

/// Records one `POST /orders` observation through the store's public recording API.
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
            limitations: Vec::new(),
        })
        .expect("begin recording");
    assert_eq!(receipt.disposition, BeginRecordingDisposition::Inserted);
}

fn read(dir: &Path, name: &str) -> String {
    fs::read_to_string(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn tree(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            if e.file_type().unwrap().is_dir() {
                walk(base, &e.path(), out);
            } else {
                let rel = e.path().strip_prefix(base).unwrap().to_string_lossy().into_owned();
                out.push((rel, fs::read(e.path()).unwrap()));
            }
        }
    }
    walk(dir, dir, &mut out);
    out
}

#[test]
fn openapi_export_is_deterministic_private_and_describes_the_catalog() {
    let fx = project_with_catalog(TRANSCRIPT);
    let a = fx.out_dir("out-a");
    let b = fx.out_dir("out-b");
    let first = fx.export(&["--format", "openapi", "--output", a.to_str().unwrap()]);
    assert_eq!(first.status.code(), Some(0), "{first:?}");
    let doc = json(&first);
    assert_eq!(doc["format"], "openapi");
    assert_eq!(doc["written"], true);
    assert_eq!(doc["preview"], false);
    assert_eq!(doc["files"][0]["path"], "openapi.json");
    let second = fx.export(&["--format", "openapi", "--output", b.to_str().unwrap()]);
    assert_eq!(second.status.code(), Some(0), "{second:?}");
    assert_eq!(json(&second)["contentHash"], doc["contentHash"]);
    assert_eq!(tree(&a), tree(&b), "byte-identical across runs");

    let spec: Value = serde_json::from_str(&read(&a, "openapi.json")).unwrap();
    assert!(spec["openapi"].as_str().unwrap().starts_with("3.1."));
    assert_eq!(spec["info"]["x-xtrace"]["revision_id"], doc["revisionId"]);
    let paths = spec["paths"].as_object().unwrap();
    assert!(paths.contains_key("/orders"), "{paths:?}");
    assert!(paths.contains_key("/orders/{id}"), "{paths:?}");
    assert!(paths.contains_key("/__fixture/count"), "{paths:?}");
    assert!(paths["/orders"].get("post").is_some());
    assert!(paths["/orders/{id}"].get("get").is_some());
    let id_param = &paths["/orders/{id}"]["get"]["parameters"][0];
    assert_eq!(
        (id_param["name"].as_str(), id_param["in"].as_str(), id_param["required"].as_bool()),
        (Some("id"), Some("path"), Some(true))
    );
    // POST /orders has a linked recording, the others were only seen statically.
    assert_eq!(paths["/orders"]["post"]["x-xtrace"]["effective_state"], "observed");
    assert_eq!(paths["/orders/{id}"]["get"]["x-xtrace"]["effective_state"], "static_only");
    let handler = &paths["/orders/{id}"]["get"]["x-xtrace"]["handlers"][0];
    assert_eq!(handler["symbol"], "OrderController.get");
    assert_eq!(handler["path"], "OrderController.java");
    assert_eq!(handler["line_start"], 30);
    assert!(handler.get("line_end").is_none(), "end line is unavailable, not the start line");
    assert!(
        json(&first)["omissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["what"] == "source" && o["reason"] == "source_end_line_unavailable")
    );

    // The output directory and its files are private.
    let dir_mode = fs::metadata(&a).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);
    let file_mode = fs::metadata(a.join("openapi.json")).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600);

    // YAML on request.
    let y = fx.out_dir("out-y");
    let yaml = fx.export(&["--format", "openapi", "--yaml", "--output", y.to_str().unwrap()]);
    assert_eq!(yaml.status.code(), Some(0), "{yaml:?}");
    assert!(read(&y, "openapi.yaml").contains("openapi:"));
}

#[test]
fn postman_and_curl_exports_have_the_expected_structure() {
    let fx = project_with_catalog(TRANSCRIPT);
    let p = fx.out_dir("out-postman");
    let postman = fx.export(&["--format", "postman", "--output", p.to_str().unwrap()]);
    assert_eq!(postman.status.code(), Some(0), "{postman:?}");
    let files = tree(&p);
    assert_eq!(files.len(), 1, "{:?}", files.iter().map(|f| &f.0).collect::<Vec<_>>());
    let collection: Value = serde_json::from_slice(&files[0].1).unwrap();
    assert!(
        collection["info"]["schema"].as_str().unwrap().contains("v2.1"),
        "{}",
        collection["info"]
    );
    let text = serde_json::to_string(&collection).unwrap();
    assert!(text.contains("{{baseUrl}}"));
    assert!(text.contains("orders"));

    let c = fx.out_dir("out-curl");
    let curl = fx.export(&["--format", "curl", "--output", c.to_str().unwrap()]);
    assert_eq!(curl.status.code(), Some(0), "{curl:?}");
    let names: Vec<String> = tree(&c).into_iter().map(|f| f.0).collect();
    assert!(names.contains(&"all.sh".to_owned()), "{names:?}");
    let scripts: Vec<&String> =
        names.iter().filter(|n| n.ends_with(".sh") && *n != "all.sh").collect();
    assert_eq!(scripts.len(), 3, "{names:?}");
    let all = read(&c, "all.sh");
    assert!(all.starts_with("#!/bin/sh\n"));
    assert!(all.contains("MUTATING"), "the POST recipe is marked");
    for name in &names {
        let mode = fs::metadata(c.join(name)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{name} is private and not executable");
    }
}

#[test]
fn preview_writes_nothing_and_lists_what_would_be_written() {
    let fx = project_with_catalog(TRANSCRIPT);
    let out = fx.out_dir("never");
    let preview = fx.export(&["--format", "curl", "--preview", "--output", out.to_str().unwrap()]);
    assert_eq!(preview.status.code(), Some(0), "{preview:?}");
    let doc = json(&preview);
    assert_eq!(doc["preview"], true);
    assert_eq!(doc["written"], false);
    assert!(doc["outputDir"].is_null());
    assert!(doc["files"].as_array().unwrap().len() >= 4);
    assert!(!out.exists(), "preview must not create the output directory");
    // No --output at all is fine for a preview.
    let bare = fx.export(&["--format", "openapi", "--preview"]);
    assert_eq!(bare.status.code(), Some(0), "{bare:?}");
}

#[test]
fn exit_codes_follow_the_cli_table() {
    let fx = project_with_catalog(TRANSCRIPT);
    let out = fx.out_dir("codes");
    let o = out.to_str().unwrap();
    // 2: usage and validation.
    for args in [
        vec!["--output", o],
        vec!["--format", "yaml-ish", "--output", o],
        vec!["--format", "openapi"],
        vec!["--format", "curl", "--yaml", "--output", o],
        vec!["--format", "openapi", "--revision", "not-a-uuid", "--output", o],
    ] {
        let output = fx.export(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(!out.exists(), "{args:?} created output");
    }
    // 3: well-formed identities that are absent, never usage errors or exit 9.
    for args in [
        vec!["--format", "openapi", "--operations", "no-such-operation", "--output", o],
        vec![
            "--format",
            "openapi",
            "--revision",
            "00000000-0000-7000-8000-000000000001",
            "--output",
            o,
        ],
    ] {
        let missing = fx.export(&args);
        assert_eq!(missing.status.code(), Some(3), "{missing:?}");
        let error: Value = serde_json::from_slice(&missing.stderr).unwrap();
        assert_eq!(error["category"], "not_found");
        assert!(missing.stdout.is_empty());
        assert!(!out.exists());
    }
    // 2: an existing output directory that is not private is refused, untouched.
    let open_dir = fx.out_dir("open-dir");
    fs::create_dir(&open_dir).unwrap();
    fs::set_permissions(&open_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let refused = fx.export(&["--format", "openapi", "--output", open_dir.to_str().unwrap()]);
    assert_eq!(refused.status.code(), Some(2), "{refused:?}");
    assert!(fs::read_dir(&open_dir).unwrap().next().is_none());
    // 2: a missing parent directory is not created implicitly.
    let deep = out.join("a/b");
    let no_parent = fx.export(&["--format", "openapi", "--output", deep.to_str().unwrap()]);
    assert_eq!(no_parent.status.code(), Some(2), "{no_parent:?}");
    assert!(!deep.exists());
    // 3: no catalog revision yet.
    let empty = self::fx();
    let none = empty.export(&["--format", "openapi", "--preview"]);
    assert_eq!(none.status.code(), Some(3), "{none:?}");
    // 3: the project directory does not exist.
    let missing = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["export", "--format", "openapi", "--preview", "--project-dir"])
        .arg(fx.out_dir("no-such-project"))
        .env("XTRACE_DATA_HOME", &fx.data_home)
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(3), "{missing:?}");
}

#[test]
fn a_selection_restricts_the_export_to_the_named_operations() {
    let fx = project_with_catalog(TRANSCRIPT);
    let list = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["catalog", "list", "--json", "--project-dir"])
        .arg(&fx.repo)
        .env("XTRACE_DATA_HOME", &fx.data_home)
        .output()
        .unwrap();
    let list = json(&list);
    let op = list["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["method"] == "GET" && o["routeTemplate"] == "/orders/{id}")
        .unwrap();
    let id = op["operationId"].as_str().unwrap();
    let out = fx.out_dir("one");
    let output = fx.export(&[
        "--format",
        "openapi",
        "--operations",
        id,
        "--operations",
        id,
        "--output",
        out.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let spec: Value = serde_json::from_str(&read(&out, "openapi.json")).unwrap();
    let paths: Vec<&String> = spec["paths"].as_object().unwrap().keys().collect();
    assert_eq!(paths, ["/orders/{id}"]);
    assert_eq!(json(&output)["operationCount"], 1);
}

/// Exports `format` and asserts the secret gate refused it: policy exit code, nothing on stdout,
/// nothing written, and the secret-shaped text never echoed.
fn assert_refused(fx: &Fx, format: &str, needle: &str) {
    let out = fx.out_dir(&format!("leak-{format}"));
    let output = fx.export(&["--format", format, "--output", out.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(8), "{format}: {output:?}");
    assert!(output.stdout.is_empty());
    let err: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(err["code"], "XTR-EXPORT-SECRET-SHAPED");
    assert_eq!(err["category"], "policy");
    assert!(!String::from_utf8_lossy(&output.stderr).contains(needle));
    assert!(!out.exists(), "{format}: nothing written");
}

#[test]
fn secret_shaped_handler_text_is_refused_by_every_format_with_the_policy_exit_code() {
    let leaky = TRANSCRIPT.replace("OrderController.get", "password=hunter2hunter2");
    let fx = project_with_catalog(&leaky);
    for format in ["openapi", "postman", "curl", "bundle"] {
        assert_refused(&fx, format, "hunter2");
    }
}

#[test]
fn secret_shaped_route_text_is_refused_by_every_format() {
    let leaky = TRANSCRIPT.replace("\"/{id}\"", "\"/keys/sk-abcdefghijklmnopqrstuvwxyz0123\"");
    let fx = project_with_catalog(&leaky);
    for format in ["openapi", "postman", "curl", "bundle"] {
        assert_refused(&fx, format, "abcdefghijklmnopqrstuvwxyz0123");
    }
}

#[test]
fn conflicting_handlers_are_summary_facts_never_synthetic_claim_locations() {
    let transcript = TRANSCRIPT
        .replace(
            r#""method":"GET","routeParts":["/orders","/{id}"]"#,
            r#""method":"POST","routeParts":["/orders"]"#,
        )
        .replace("OrderController.get", "AController.other");
    let fx = project_with_catalog(&transcript);
    for format in ["openapi", "postman", "curl", "bundle"] {
        let out = fx.out_dir(&format!("conflict-{format}"));
        let result = fx.export(&["--format", format, "--output", out.to_str().unwrap()]);
        assert_eq!(result.status.code(), Some(0), "{result:?}");
        assert_eq!(json(&result)["operationCount"], 2);
        let all = tree(&out)
            .into_iter()
            .map(|(_, bytes)| String::from_utf8(bytes).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        for symbol in ["AController.other", "OrderController.create"] {
            assert!(all.contains(symbol), "{format} lost {symbol}");
        }
        let omissions = json(&result)["omissions"].as_array().unwrap().clone();
        for reason in [
            "handler_conflict_unresolved",
            "per_claim_locations_unavailable",
            "per_claim_confidence_unavailable",
        ] {
            assert!(omissions.iter().any(|o| o["reason"] == reason), "{omissions:?}");
        }
        if format == "openapi" {
            let spec: Value = serde_json::from_str(&read(&out, "openapi.json")).unwrap();
            let x = &spec["paths"]["/orders"]["post"]["x-xtrace"];
            assert_eq!(
                x["handler_symbols"],
                serde_json::json!(["AController.other", "OrderController.create"])
            );
            assert_eq!(x["handler_conflict"], true);
            assert_eq!(x["claim_count"], 2);
            assert_eq!(x["claims_projection"], "unavailable");
            assert!(x["highest_confidence_basis_points"].as_u64().is_some());
            assert!(x.get("confidence_basis_points").is_none());
            assert!(x.get("handlers").is_none(), "no fabricated symbol/location pairs");
            assert!(x.get("line_end").is_none(), "no fabricated one-line extent");
        }
    }
}

/// Assemble a multi-scope revision from two real scans. Current scan scopes each
/// publish their own revision; this fixture exercises the history port's wider
/// revision representation without inventing operations or claim JSON.
fn add_scope_to_revision(fx: &Fx, component: &str, binding: &str) -> String {
    let connection = rusqlite::Connection::open(fx.database()).unwrap();
    connection.pragma_update(None, "foreign_keys", true).unwrap();
    let original: Vec<u8> = connection
        .query_row(
            "SELECT revision_id FROM catalog_revisions ORDER BY revision_id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let analyzer = fx.write_analyzer(TRANSCRIPT);
    let scan = fx.scan_scope(&analyzer, component, binding);
    assert_eq!(scan.status.code(), Some(0), "{scan:?}");
    let connection = rusqlite::Connection::open(fx.database()).unwrap();
    connection.pragma_update(None, "foreign_keys", true).unwrap();
    let newer: Vec<u8> = connection.query_row(
        "SELECT revision_id FROM catalog_revisions WHERE revision_id != ?1 ORDER BY revision_id DESC LIMIT 1",
        [&original], |row| row.get(0)
    ).unwrap();
    connection.execute(
        "INSERT INTO catalog_revision_entries (project_id, revision_id, operation_id, operation_version_id, change_kind, source_availability)
         SELECT project_id, ?1, operation_id, operation_version_id, change_kind, source_availability
         FROM catalog_revision_entries WHERE revision_id = ?2",
        rusqlite::params![newer, original],
    ).unwrap();
    connection.execute(
        "INSERT INTO catalog_revision_claims (project_id, revision_id, operation_id, claim_id)
         SELECT project_id, ?1, operation_id, claim_id FROM catalog_revision_claims WHERE revision_id = ?2",
        rusqlite::params![newer, original],
    ).unwrap();
    connection.execute(
        "UPDATE catalog_revisions SET operation_count = (SELECT COUNT(*) FROM catalog_revision_entries WHERE revision_id = ?1) WHERE revision_id = ?1",
        [&newer],
    ).unwrap();
    uuid::Uuid::from_slice(&newer).unwrap().to_string()
}

#[test]
fn observations_keep_component_and_binding_scope_and_counts_match_each_format() {
    // Each axis must be checked independently. Canonical OpenAPI chooses the
    // unobserved scope first in both cases, so a route-only join fails visibly.
    for (component, binding) in [("a-component", "default"), ("spring-fixture", "a-binding")] {
        let fx = project_with_catalog(TRANSCRIPT);
        let revision = add_scope_to_revision(&fx, component, binding);
        for format in ["openapi", "postman", "curl", "bundle"] {
            let out = fx.out_dir(&format!("scoped-{format}"));
            let result = fx.export(&[
                "--format",
                format,
                "--revision",
                &revision,
                "--output",
                out.to_str().unwrap(),
            ]);
            assert_eq!(result.status.code(), Some(0), "{result:?}");
            let expected_count = if format == "openapi" { 3 } else { 6 };
            assert_eq!(json(&result)["operationCount"], expected_count);
            if format == "openapi" {
                let spec: Value = serde_json::from_str(&read(&out, "openapi.json")).unwrap();
                let op = &spec["paths"]["/orders"]["post"];
                assert_eq!(op["x-xtrace"]["effective_state"], "static_only");
                assert_eq!(op["x-xtrace-observation"], "inferred");
                let omissions = json(&result)["omissions"].as_array().unwrap().clone();
                assert_eq!(
                    omissions
                        .iter()
                        .filter(|o| o["reason"]
                            .as_str()
                            .unwrap()
                            .starts_with("duplicate_method_path_of:"))
                        .count(),
                    3
                );
            } else if format == "postman" {
                let doc: Value =
                    serde_json::from_str(&read(&out, "collection.postman.json")).unwrap();
                let items = doc["item"].as_array().unwrap();
                assert_eq!(items.len(), 6);
                let descriptions: Vec<_> =
                    items.iter().map(|i| i["request"]["description"].as_str().unwrap()).collect();
                assert_eq!(
                    descriptions.iter().filter(|d| d.contains("catalog state: observed")).count(),
                    1
                );
                assert_eq!(
                    descriptions
                        .iter()
                        .filter(|d| d.contains("catalog state: static_only"))
                        .count(),
                    5
                );
            } else if format == "curl" {
                let scripts: Vec<_> =
                    tree(&out).into_iter().filter(|(name, _)| name != "all.sh").collect();
                assert_eq!(scripts.len(), 6);
                assert_eq!(
                    scripts
                        .iter()
                        .filter(|(_, bytes)| String::from_utf8_lossy(bytes)
                            .contains("# catalog state: observed\n"))
                        .count(),
                    1
                );
            } else {
                let manifest: Value = serde_json::from_str(&read(&out, "manifest.json")).unwrap();
                let formats = manifest["formats"].as_array().unwrap();
                assert_eq!(formats[0]["operation_count"], 3);
                assert_eq!(formats[1]["operation_count"], 6);
                assert_eq!(formats[2]["operation_count"], 6);
                assert_eq!(manifest["operation_count"], 6);
            }
        }
    }
}

#[test]
fn existing_output_is_refused_without_stale_or_mixed_files() {
    let fx = project_with_catalog(TRANSCRIPT);
    for format in ["openapi", "postman", "curl", "bundle"] {
        let out = fx.out_dir(&format!("existing-{format}"));
        fs::create_dir(&out).unwrap();
        fs::set_permissions(&out, fs::Permissions::from_mode(0o700)).unwrap();
        // An existing empty private directory is a supported destination.
        let first = fx.export(&["--format", format, "--output", out.to_str().unwrap()]);
        assert_eq!(first.status.code(), Some(0), "{first:?}");
        fs::write(out.join("keep.txt"), b"unrelated user content").unwrap();
        let before = tree(&out);
        let entries_before = fs::read_dir(fx._root.path()).unwrap().count();
        for next in [format, "curl"] {
            let again = fx.export(&["--format", next, "--output", out.to_str().unwrap()]);
            assert_eq!(again.status.code(), Some(2), "{again:?}");
            assert!(again.stdout.is_empty());
            assert_eq!(tree(&out), before);
            assert_eq!(
                fs::read_dir(fx._root.path()).unwrap().count(),
                entries_before,
                "no staging leftovers"
            );
        }
    }
    let target = fx.out_dir("link-target");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    let link = fx.out_dir("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let refused = fx.export(&["--format", "bundle", "--output", link.to_str().unwrap()]);
    assert_eq!(refused.status.code(), Some(2), "{refused:?}");
    assert!(tree(&target).is_empty());
    assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
}

#[test]
fn bundle_contains_deterministic_payload_hashes_counts_and_explicit_policy_gap() {
    let fx = project_with_catalog(TRANSCRIPT);
    let a = fx.out_dir("bundle-a");
    let b = fx.out_dir("bundle-b");
    let preview = fx.export(&["--format", "bundle", "--preview"]);
    assert_eq!(preview.status.code(), Some(0), "{preview:?}");
    let mut results = Vec::new();
    for out in [&a, &b] {
        let result = fx.export(&["--format", "bundle", "--output", out.to_str().unwrap()]);
        assert_eq!(result.status.code(), Some(0), "{result:?}");
        assert_eq!(json(&result)["operationCount"], 3);
        results.push(json(&result));
        assert_eq!(fs::metadata(out).unwrap().permissions().mode() & 0o777, 0o700);
        for (name, _) in tree(out) {
            assert_eq!(fs::metadata(out.join(name)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(fs::metadata(out.join("curl")).unwrap().permissions().mode() & 0o777, 0o700);
    }
    assert_eq!(results[0]["contentHash"], results[1]["contentHash"]);
    assert_eq!(results[0]["contentHash"], json(&preview)["contentHash"]);
    assert_eq!(tree(&a), tree(&b));
    assert!(a.join("openapi.yaml").is_file());
    assert!(a.join("collection.postman.json").is_file());
    assert!(a.join("curl/all.sh").is_file());
    assert!(read(&a, "README.md").contains("Omissions (format prefixes"));
    let manifest: Value = serde_json::from_str(&read(&a, "manifest.json")).unwrap();
    assert_eq!(manifest["revision_id"], results[0]["revisionId"]);
    assert_eq!(manifest["catalog_hash"].as_str().unwrap().len(), 64);
    assert!(manifest["policy_digest"].is_null());
    assert!(manifest["omissions"].as_array().unwrap().iter().any(|o| o["what"] == "policy_digest" && o["reason"] == "not_available_in_catalog_view"));
    let files = manifest["files"].as_array().unwrap();
    assert_eq!(files.len(), 6);
    assert_eq!(tree(&a).len(), 8, "only payload, manifest and README");
    for file in files {
        let bytes = fs::read(a.join(file["path"].as_str().unwrap())).unwrap();
        assert_eq!(file["bytes"], bytes.len());
        assert_eq!(file["blake3"], blake3::hash(&bytes).to_hex().to_string());
    }
}
