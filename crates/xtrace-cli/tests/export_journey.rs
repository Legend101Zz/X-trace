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

fn openapi_metadata(dir: &Path, route: &str, method: &str) -> Value {
    let spec: Value = serde_json::from_str(&read(dir, "openapi.json")).unwrap();
    spec["paths"][route][method]["x-xtrace"].clone()
}

fn comment_metadata(text: &str) -> Option<Value> {
    text.lines().find_map(|line| {
        let json = line.trim_start_matches("# ").strip_prefix("x-xtrace catalog metadata: ")?;
        Some(serde_json::from_str(json).unwrap())
    })
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
    let metadata = &paths["/orders/{id}"]["get"]["x-xtrace"];
    let claim = &metadata["claims"][0];
    assert_eq!(metadata["claims_projection"], "available");
    assert_eq!(metadata["claim_count"], 1);
    assert_eq!(claim["handler_symbol"], "OrderController.get");
    assert_eq!(claim["confidence_basis_points"], 5000);
    let evidence = &claim["source_evidence"][0];
    assert_eq!(evidence["relative_path"], "OrderController.java");
    assert_eq!(evidence["start_line"], 30);
    assert_eq!(evidence["end_line"], 31);
    assert_eq!(evidence["verification"], "unverified");
    assert!(
        json(&first)["omissions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|o| o["reason"] != "source_end_line_unavailable")
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
    for symbol in [
        "password=hunter2hunter2",
        "src/routes.js#password:hunter2hunter2",
        "src/(private routes)/token=hunter2hunter2.js#list",
    ] {
        let leaky = TRANSCRIPT.replace("OrderController.get", symbol);
        let fx = project_with_catalog(&leaky);
        for format in ["openapi", "postman", "curl", "bundle"] {
            assert_refused(&fx, format, "hunter2");
        }
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

fn stored_claim(connection: &rusqlite::Connection, symbol: &str) -> (Vec<u8>, Value) {
    let (id, json): (Vec<u8>, String) = connection
        .query_row(
            "SELECT claim_id, canonical_json FROM catalog_claims
             WHERE json_extract(canonical_json, '$.handler_symbol') = ?1",
            [symbol],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    (id, serde_json::from_str(&json).unwrap())
}

fn rebuild_fixture_claim(
    value: &Value,
) -> xtrace_domain::catalog_discovery::ValidatedEndpointClaim {
    use xtrace_domain::catalog_discovery::ValidatedEndpointClaim;
    use xtrace_domain::{EndpointIdentity, Transport};

    ValidatedEndpointClaim::from_persisted(
        value["claim_hint"].as_str().unwrap().to_owned(),
        EndpointIdentity {
            project_id: serde_json::from_value(value["project_id"].clone()).unwrap(),
            application_component: value["application_component"].as_str().unwrap().to_owned(),
            binding_key: value["binding_key"].as_str().unwrap().to_owned(),
            method: serde_json::from_value(value["method"].clone()).unwrap(),
            route_template: value["route_template"].as_str().unwrap().to_owned(),
            transport: Transport::Http,
        },
        serde_json::from_value(value["provenance"].clone()).unwrap(),
        serde_json::from_value(value["handler_symbol"].clone()).unwrap(),
        serde_json::from_value(value["confidence_basis_points"].clone()).unwrap(),
        serde_json::from_value(value["limitation_codes"].clone()).unwrap(),
        serde_json::from_value(value["source_evidence"].clone()).unwrap(),
    )
    .unwrap()
}

fn replace_claim_payload(
    connection: &rusqlite::Connection,
    id: &[u8],
    digest: &[u8],
    canonical: &[u8],
    json: &str,
) {
    assert_eq!(
        connection
            .execute(
                "UPDATE catalog_claims
                 SET claim_digest = ?1, canonical_bytes = ?2, canonical_json = ?3
                 WHERE claim_id = ?4",
                rusqlite::params![digest, canonical, json, id],
            )
            .unwrap(),
        1
    );
}

// The scripted analyzer emits one evidence item per claim. Build consistent rows for evidence
// shapes beyond that output using the domain's canonical encoder.
fn edit_claim(fx: &Fx, symbol: &str, edit: impl FnOnce(&mut Value)) -> String {
    let mut connection = rusqlite::Connection::open(fx.database()).unwrap();
    let tx = connection.transaction().unwrap();
    let (id, mut value) = stored_claim(&tx, symbol);
    edit(&mut value);
    let claim = rebuild_fixture_claim(&value);
    value["source_evidence"] = serde_json::json!(claim.source_evidence());
    replace_claim_payload(
        &tx,
        &id,
        claim.digest().unwrap().as_bytes(),
        claim.canonical_bytes(),
        &value.to_string(),
    );
    // These fixtures synthesize valid claim variants. Update the version's claim-set
    // digest as the publisher would, leaving corruption tests to edit rows directly.
    let (revision_id, operation_id): (Vec<u8>, Vec<u8>) = tx
        .query_row(
            "SELECT first_revision_id, operation_id FROM catalog_claims WHERE claim_id = ?1",
            [&id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    refresh_fixture_version(&tx, &revision_id, &operation_id);
    tx.commit().unwrap();
    uuid::Uuid::from_slice(&id).unwrap().to_string()
}

fn refresh_fixture_version(
    connection: &rusqlite::Connection,
    revision_id: &[u8],
    operation_id: &[u8],
) {
    let (version_id, fingerprint): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT e.operation_version_id, o.endpoint_fingerprint FROM catalog_revision_entries e
             JOIN catalog_operations o ON o.project_id = e.project_id AND o.operation_id = e.operation_id
             WHERE e.revision_id = ?1 AND e.operation_id = ?2",
            rusqlite::params![revision_id, operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"xtrace.operation-version.v1\0");
    hasher.update(&fingerprint);
    let mut statement = connection
        .prepare(
            "SELECT c.claim_digest FROM catalog_revision_claims rc
             JOIN catalog_claims c ON c.project_id = rc.project_id
                 AND c.operation_id = rc.operation_id AND c.claim_id = rc.claim_id
             WHERE rc.revision_id = ?1 AND rc.operation_id = ?2 ORDER BY c.claim_digest",
        )
        .unwrap();
    let digests = statement
        .query_map(rusqlite::params![revision_id, operation_id], |row| row.get::<_, Vec<u8>>(0))
        .unwrap();
    for digest in digests {
        hasher.update(&digest.unwrap());
    }
    assert_eq!(
        connection
            .execute(
                "UPDATE catalog_operation_versions SET version_digest = ?1 WHERE operation_version_id = ?2",
                rusqlite::params![hasher.finalize().as_bytes().as_slice(), version_id],
            )
            .unwrap(),
        1
    );
}

fn assert_corrupt_export(fx: &Fx, format: &str, revision: Option<&str>, name: &str) {
    let out = fx.out_dir(name);
    let mut args = vec!["--format", format, "--output", out.to_str().unwrap()];
    if let Some(revision) = revision {
        args.extend(["--revision", revision]);
    }
    let result = fx.export(&args);
    assert_eq!(result.status.code(), Some(5), "{name}: {result:?}");
    assert!(result.stdout.is_empty());
    let error: Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(error["code"], "XTR-CLI-STORE-UNAVAILABLE");
    assert!(
        error["message"].as_str().unwrap().contains("catalog history evidence is inconsistent")
    );
    assert!(!out.exists());
}

#[test]
fn export_rejects_inconsistent_persisted_claims_without_output() {
    use serde_json::json;

    let fx = project_with_catalog(TRANSCRIPT);
    let before = fx.out_dir("before-corruption");
    let result = fx.export(&["--format", "openapi", "--output", before.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let connection = rusqlite::Connection::open(fx.database()).unwrap();
    let (id, value) = stored_claim(&connection, "OrderController.get");
    let (digest, canonical, original_json): (Vec<u8>, Vec<u8>, String) = connection
        .query_row(
            "SELECT claim_digest, canonical_bytes, canonical_json FROM catalog_claims WHERE claim_id = ?1",
            [&id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let original = rebuild_fixture_claim(&value);
    assert_eq!(original.canonical_bytes(), canonical);
    assert_eq!(original.digest().unwrap().as_bytes().as_slice(), digest);

    for (field, replacement) in [
        ("handler_symbol", json!("OrderController.other")),
        ("confidence_basis_points", json!(9100)),
        ("limitation_codes", json!(["missing_response_schema"])),
        ("provenance", json!("runtime_discovered")),
        ("source_evidence", {
            let mut evidence = value["source_evidence"].clone();
            evidence[0]["end_column"] = json!(41);
            evidence
        }),
    ] {
        let mut edited = value.clone();
        edited[field] = replacement;
        assert_ne!(rebuild_fixture_claim(&edited).canonical_bytes(), canonical, "{field}");
        replace_claim_payload(&connection, &id, &digest, &canonical, &edited.to_string());
        assert_corrupt_export(&fx, "openapi", None, field);
    }

    let mut wrong_bytes = canonical.clone();
    *wrong_bytes.last_mut().unwrap() ^= 1;
    replace_claim_payload(&connection, &id, &digest, &wrong_bytes, &original_json);
    assert_corrupt_export(&fx, "postman", None, "wrong-bytes");

    let mut wrong_digest = digest.clone();
    wrong_digest[0] ^= 1;
    replace_claim_payload(&connection, &id, &wrong_digest, &canonical, &original_json);
    assert_corrupt_export(&fx, "curl", None, "wrong-digest");

    // All three representations agree here. The payload belongs to a different operation.
    let mut wrong_operation = value.clone();
    wrong_operation["route_template"] = json!("/other");
    let claim = rebuild_fixture_claim(&wrong_operation);
    replace_claim_payload(
        &connection,
        &id,
        claim.digest().unwrap().as_bytes(),
        claim.canonical_bytes(),
        &wrong_operation.to_string(),
    );
    assert_corrupt_export(&fx, "bundle", None, "wrong-operation");

    replace_claim_payload(&connection, &id, &digest, &canonical, &original_json);
    let restored = fx.out_dir("restored");
    let result = fx.export(&["--format", "openapi", "--output", restored.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(tree(&restored), tree(&before));
}

#[test]
fn export_rejects_missing_published_claim_links_without_output() {
    let fx = project_with_catalog(TRANSCRIPT);
    // The second scan publishes two distinct claims for POST /orders and inherits
    // GET /orders/{id} with no links in the new revision.
    let next = TRANSCRIPT.replace(
        r#""method":"GET","routeParts":["/orders","/{id}"]"#,
        r#""method":"POST","routeParts":["/orders"]"#,
    );
    let scan = fx.scan(&fx.write_analyzer(&next));
    assert_eq!(scan.status.code(), Some(0), "{scan:?}");
    let scan = json(&scan);
    let revision = scan["catalogRevisionId"].as_str().unwrap();
    let formats = ["openapi", "postman", "curl", "bundle"];
    let export_to = |format, out: &Path| {
        let result = fx.export(&[
            "--format",
            format,
            "--revision",
            revision,
            "--output",
            out.to_str().unwrap(),
        ]);
        assert_eq!(result.status.code(), Some(0), "{result:?}");
        result
    };
    for format in formats {
        export_to(format, &fx.out_dir(&format!("intact-{format}")));
    }
    let intact = fx.out_dir("intact-openapi");
    let published = openapi_metadata(&intact, "/orders", "post");
    assert_eq!(published["claims_projection"], "available");
    assert_eq!(published["claim_count"], 2);
    assert_eq!(published["handler_conflict"], true);
    let inherited = openapi_metadata(&intact, "/orders/{id}", "get");
    assert_eq!(inherited["effective_state"], "unknown");
    assert_eq!(inherited["claims_projection"], "unavailable");
    for field in ["claim_count", "claims", "handler_conflict"] {
        assert!(inherited.get(field).is_none(), "{field}");
    }

    let parse_id = |value: &Value| uuid::Uuid::parse_str(value.as_str().unwrap()).unwrap();
    let project = uuid::Uuid::parse_str(&fx.project_id).unwrap();
    let revision_id = uuid::Uuid::parse_str(revision).unwrap();
    let operation = parse_id(&published["operation_id"]);
    let claim_ids = [
        parse_id(&published["claims"][0]["claim_id"]),
        parse_id(&published["claims"][1]["claim_id"]),
    ];
    let mut connection = rusqlite::Connection::open(fx.database()).unwrap();
    connection.pragma_update(None, "foreign_keys", true).unwrap();
    let (kind, availability): (String, String) = connection
        .query_row(
            "SELECT change_kind, source_availability FROM catalog_revision_entries
             WHERE project_id = ?1 AND revision_id = ?2 AND operation_id = ?3",
            rusqlite::params![project.as_bytes(), revision_id.as_bytes(), operation.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(kind, "changed");
    assert_eq!(availability, "unverified");
    for (case, claim_id) in ["partial", "missing"].into_iter().zip(claim_ids) {
        assert_eq!(
            connection
                .execute(
                    "DELETE FROM catalog_revision_claims
                     WHERE project_id = ?1 AND revision_id = ?2 AND operation_id = ?3 AND claim_id = ?4",
                    rusqlite::params![project.as_bytes(), revision_id.as_bytes(), operation.as_bytes(), claim_id.as_bytes()],
                )
                .unwrap(),
            1
        );
        for format in formats {
            assert_corrupt_export(&fx, format, Some(revision), &format!("{case}-{format}"));
        }
    }

    let tx = connection.transaction().unwrap();
    for claim_id in claim_ids {
        assert_eq!(
            tx.execute(
                "INSERT INTO catalog_revision_claims (project_id, revision_id, operation_id, claim_id)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![project.as_bytes(), revision_id.as_bytes(), operation.as_bytes(), claim_id.as_bytes()],
            )
            .unwrap(),
            1
        );
    }
    tx.commit().unwrap();
    for format in formats {
        let restored = fx.out_dir(&format!("restored-{format}"));
        let result = export_to(format, &restored);
        assert!(json(&result)["omissions"].as_array().unwrap().iter().any(|item| {
            item["operationId"] == inherited["operation_id"]
                && item["reason"] == "claims_projection_unavailable"
        }));
        assert_eq!(tree(&restored), tree(&fx.out_dir(&format!("intact-{format}"))), "{format}");
    }
}

#[test]
fn export_distinct_claim_locations_and_confidences() {
    let transcript = TRANSCRIPT
        .replace(
            r#""method":"GET","routeParts":["/orders","/{id}"]"#,
            r#""method":"POST","routeParts":["/orders"]"#,
        )
        .replace("OrderController.get", "AController.other");
    let fx = project_with_catalog(&transcript);
    let additional = {
        let connection = rusqlite::Connection::open(fx.database()).unwrap();
        stored_claim(&connection, "FixtureAdminController.count").1["source_evidence"][0].clone()
    };
    let other_id = edit_claim(&fx, "AController.other", |claim| {
        claim["source_evidence"].as_array_mut().unwrap().push(additional);
    });
    let create_id = edit_claim(&fx, "OrderController.create", |claim| {
        claim["limitation_codes"] = serde_json::json!(["missing_response_schema"]);
    });
    let mut expected_claims = Value::Null;
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
        let doc = json(&result);
        let omissions = doc["omissions"].as_array().unwrap();
        assert!(omissions.iter().any(|o| o["reason"] == "handler_conflict_unresolved"));
        assert!(omissions.iter().all(|o| {
            o["reason"] != "per_claim_locations_unavailable"
                && o["reason"] != "per_claim_confidence_unavailable"
        }));
        let postman_metadata = || {
            let doc: Value = serde_json::from_str(&read(&out, "collection.postman.json")).unwrap();
            let request = doc["item"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["name"] == "POST /orders")
                .unwrap();
            comment_metadata(request["request"]["description"].as_str().unwrap()).unwrap()
        };
        let curl_metadata = || {
            tree(&out)
                .into_iter()
                .filter(|(name, _)| name.ends_with("-post-orders.sh"))
                .find_map(|(_, bytes)| comment_metadata(&String::from_utf8(bytes).unwrap()))
                .unwrap()
        };
        let metadata = match format {
            "openapi" => openapi_metadata(&out, "/orders", "post"),
            "postman" => postman_metadata(),
            "curl" => curl_metadata(),
            "bundle" => {
                let yaml = read(&out, "openapi.yaml");
                for id in [&other_id, &create_id] {
                    assert!(yaml.contains(id));
                }
                let metadata = postman_metadata();
                assert_eq!(metadata, curl_metadata());
                let block =
                    xtrace_export::canonical::yaml(&serde_json::json!({"x-xtrace": metadata}));
                let block = block.lines().map(|line| format!("      {line}\n")).collect::<String>();
                assert!(yaml.contains(&block));
                metadata
            }
            _ => unreachable!(),
        };
        if format == "openapi" {
            assert_eq!(
                metadata["handler_symbols"],
                serde_json::json!(["AController.other", "OrderController.create"])
            );
            assert!(metadata.get("highest_confidence_basis_points").is_none());
            assert!(metadata.get("confidence_basis_points").is_none());
            assert!(metadata.get("handlers").is_none(), "locations belong to claims");
            assert!(metadata.get("line_end").is_none(), "no operation-level range");
            expected_claims = metadata["claims"].clone();
        }
        assert_eq!(metadata["handler_conflict"], true);
        assert_eq!(metadata["claim_count"], 2);
        assert_eq!(metadata["claims_projection"], "available");
        assert_eq!(metadata["claims"], expected_claims);
        let claims = metadata["claims"].as_array().unwrap();
        for (id, symbol, confidence, locations) in [
            (
                &other_id,
                "AController.other",
                5000,
                &[("OrderController.java", 30, 31), ("FixtureAdminController.java", 20, 21)][..],
            ),
            (&create_id, "OrderController.create", 9000, &[("OrderController.java", 23, 24)][..]),
        ] {
            let claim = claims
                .iter()
                .find(|claim| claim["claim_id"].as_str() == Some(id.as_str()))
                .unwrap();
            assert_eq!(claim["handler_symbol"], symbol);
            assert_eq!(claim["confidence_basis_points"], confidence);
            assert_eq!(claim["provenance"], "static_inferred");
            let evidence = claim["source_evidence"].as_array().unwrap();
            assert_eq!(evidence.len(), locations.len());
            for (evidence, (path, start, end)) in evidence.iter().zip(locations) {
                assert_eq!(evidence["kind"], "static_snapshot");
                assert_eq!(evidence["relative_path"], *path);
                assert_eq!(evidence["start_line"], *start);
                assert_eq!(evidence["end_line"], *end);
                assert_eq!(evidence["verification"], "unverified");
                assert!(evidence["source_revision_id"].as_str().is_some());
                assert!(evidence["recorded_source_digest"].as_str().is_some());
            }
            if id == &create_id {
                assert_eq!(
                    claim["limitation_codes"],
                    serde_json::json!(["missing_response_schema"])
                );
            } else {
                assert_eq!(claim.get("limitation_codes"), Some(&serde_json::json!([])));
            }
        }
    }
}

#[test]
fn export_revision_claims_survive_restart_without_cross_revision_leakage() {
    use xtrace_application::catalog_discovery::history::CatalogHistoryPort;
    use xtrace_domain::{CatalogRevisionId, ProjectId};
    use xtrace_store::catalog_history_store::SqliteCatalogHistoryStore;
    use xtrace_store::{OpenOptions, SqliteStore};

    let fx = project_with_catalog(TRANSCRIPT);
    let before = fx.out_dir("before");
    let export = fx.export(&["--format", "openapi", "--output", before.to_str().unwrap()]);
    assert_eq!(export.status.code(), Some(0), "{export:?}");
    let first = json(&export);
    let old_revision = first["revisionId"].as_str().unwrap();
    let old_orders = openapi_metadata(&before, "/orders", "post");
    let old_carried = openapi_metadata(&before, "/orders/{id}", "get");

    let next = TRANSCRIPT
        .lines()
        .enumerate()
        .filter(|(index, _)| *index != 2)
        .map(|(_, line)| {
            line.replace("OrderController.create", "OrderController.createUpdated")
                .replace("\"claims\":3", "\"claims\":2")
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let scan = fx.scan(&fx.write_analyzer(&next));
    assert_eq!(scan.status.code(), Some(0), "{scan:?}");
    let scan_doc = json(&scan);
    let new_revision = scan_doc["catalogRevisionId"].as_str().unwrap();
    assert_ne!(old_revision, new_revision);
    assert_eq!(scan_doc["parentRevisionId"], old_revision);

    // Every export opens the catalog in a new process.
    let latest = fx.out_dir("latest");
    let export = fx.export(&[
        "--format",
        "openapi",
        "--revision",
        new_revision,
        "--output",
        latest.to_str().unwrap(),
    ]);
    assert_eq!(export.status.code(), Some(0), "{export:?}");
    assert_eq!(json(&export)["operationCount"], 3);
    let new_orders = openapi_metadata(&latest, "/orders", "post");
    assert_eq!(new_orders["operation_id"], old_orders["operation_id"]);
    assert_eq!(new_orders["claim_count"], 1);
    assert_ne!(new_orders["claims"][0]["claim_id"], old_orders["claims"][0]["claim_id"]);
    assert_eq!(new_orders["claims"][0]["handler_symbol"], "OrderController.createUpdated");
    let carried = openapi_metadata(&latest, "/orders/{id}", "get");
    assert_eq!(carried["operation_id"], old_carried["operation_id"]);
    assert_eq!(carried["effective_state"], "unknown");
    assert_eq!(carried["claims_projection"], "unavailable");
    for field in ["claim_count", "claims", "handler_symbols", "handler_conflict", "handlers"] {
        assert!(carried.get(field).is_none(), "{field}");
    }
    let assert_omission = |result: &Output| {
        assert!(json(result)["omissions"].as_array().unwrap().iter().any(|item| {
            item["operationId"] == carried["operation_id"]
                && item["reason"] == "claims_projection_unavailable"
        }));
    };
    assert_omission(&export);
    let old_claim = old_carried["claims"][0]["claim_id"].as_str().unwrap();
    assert!(!read(&latest, "openapi.json").contains(old_claim));

    for format in ["postman", "curl", "bundle"] {
        let out = fx.out_dir(format);
        let result = fx.export(&[
            "--format",
            format,
            "--revision",
            new_revision,
            "--output",
            out.to_str().unwrap(),
        ]);
        assert_eq!(result.status.code(), Some(0), "{result:?}");
        assert_eq!(json(&result)["operationCount"], 3);
        assert_omission(&result);
        let files = tree(&out);
        for (_, bytes) in &files {
            assert!(!std::str::from_utf8(bytes).unwrap().contains(old_claim), "{format}");
        }
        if format != "curl" {
            let doc: Value = serde_json::from_str(&read(&out, "collection.postman.json")).unwrap();
            let item = doc["item"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["name"] == "GET /orders/{id}")
                .unwrap();
            assert_eq!(
                comment_metadata(item["request"]["description"].as_str().unwrap()),
                Some(carried.clone())
            );
        }
        if format != "postman" {
            let recipe =
                files.iter().find(|(name, _)| name.ends_with("-get-orders-id.sh")).unwrap();
            assert_eq!(
                comment_metadata(std::str::from_utf8(&recipe.1).unwrap()),
                Some(carried.clone())
            );
        }
        if format == "bundle" {
            let block = xtrace_export::canonical::yaml(&serde_json::json!({"x-xtrace": carried}));
            let block = block.lines().map(|line| format!("      {line}\n")).collect::<String>();
            assert!(read(&out, "openapi.yaml").contains(&block));
        }
    }

    let historical = fx.out_dir("historical");
    let export = fx.export(&[
        "--format",
        "openapi",
        "--revision",
        old_revision,
        "--output",
        historical.to_str().unwrap(),
    ]);
    assert_eq!(export.status.code(), Some(0), "{export:?}");
    assert_eq!(tree(&historical), tree(&before));

    let store =
        SqliteStore::open(&fx.database(), OpenOptions::default().with_must_exist(true)).unwrap();
    let history = SqliteCatalogHistoryStore::new(store);
    let revision = CatalogRevisionId::from_uuid(uuid::Uuid::parse_str(new_revision).unwrap());
    let project = ProjectId::from_uuid(uuid::Uuid::parse_str(&fx.project_id).unwrap());
    let current = history.revision_operations(project, revision).unwrap();
    let previous = history
        .revision_operations(
            project,
            CatalogRevisionId::from_uuid(uuid::Uuid::parse_str(old_revision).unwrap()),
        )
        .unwrap();
    let before = previous.iter().find(|op| op.route_template == "/orders/{id}").unwrap();
    let after = current.iter().find(|op| op.operation_id == before.operation_id).unwrap();
    assert_eq!(after.operation_version_id, before.operation_version_id);
    assert_eq!(after.change_kind, xtrace_application::CatalogChangeKind::Unknown);
    assert_eq!(
        after.source_availability,
        xtrace_application::CatalogSourceAvailability::Unavailable
    );
    assert!(before.claims_available);
    assert!(!after.claims_available);
    assert!(after.claims.is_empty());
    assert!(history.revision_operations(ProjectId::new(), revision).unwrap().is_empty());
}

#[test]
fn export_missing_claim_fields_remain_unknown() {
    let fx = project_with_catalog(TRANSCRIPT);
    let id = edit_claim(&fx, "OrderController.get", |claim| {
        let fields = claim.as_object_mut().unwrap();
        fields.remove("handler_symbol");
        fields.remove("confidence_basis_points");
        claim["source_evidence"] = serde_json::json!([
            {"kind": "runtime_hint", "relative_path": "OrderController.java",
                "start_line": 30, "start_column": 3},
            {"kind": "unavailable", "reason_code": "debug_metadata_absent"}
        ]);
    });
    edit_claim(&fx, "OrderController.create", |claim| {
        claim["source_evidence"] = serde_json::json!([]);
    });
    let out = fx.out_dir("missing");
    let result = fx.export(&["--format", "openapi", "--output", out.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let metadata = openapi_metadata(&out, "/orders/{id}", "get");
    let claim = &metadata["claims"][0];
    assert_eq!(claim["claim_id"], id);
    assert_eq!(claim.get("handler_symbol"), Some(&Value::Null));
    assert_eq!(metadata.get("handler_symbols"), Some(&Value::Null));
    assert_eq!(metadata.get("handler_conflict"), Some(&Value::Null));
    assert_eq!(claim.get("confidence_basis_points"), Some(&Value::Null));
    assert!(metadata.get("confidence_basis_points").is_none());
    assert!(metadata.get("handlers").is_none());
    let evidence = claim["source_evidence"].as_array().unwrap();
    assert_eq!(evidence.len(), 2);
    let unavailable = &evidence[0];
    assert_eq!(unavailable["kind"], "unavailable");
    assert_eq!(unavailable["verification"], "unavailable");
    assert_eq!(unavailable["reason_code"], "debug_metadata_absent");
    assert_eq!(unavailable.get("relative_path"), Some(&Value::Null));
    let hint = &evidence[1];
    assert_eq!(hint["kind"], "runtime_hint");
    assert_eq!(hint["start_line"], 30);
    assert_eq!(hint["verification"], "unverified");
    assert_eq!(hint.get("end_line"), Some(&Value::Null));
    assert_eq!(hint.get("end_column"), Some(&Value::Null));
    assert_eq!(
        openapi_metadata(&out, "/orders", "post")["claims"][0]["source_evidence"],
        serde_json::json!([])
    );
}

#[test]
fn export_refuses_tampered_unsafe_claim_locations() {
    let fx = project_with_catalog(TRANSCRIPT);
    let connection = rusqlite::Connection::open(fx.database()).unwrap();
    let (id, mut claim) = stored_claim(&connection, "OrderController.get");
    let unsafe_paths = ["/outside/export-private.java", "../traversal.java", r"Q:\drive.java"];
    let items = claim["source_evidence"].as_array_mut().unwrap();
    let safe = items[0].clone();
    for path in unsafe_paths {
        let mut unsafe_item = safe.clone();
        unsafe_item["relative_path"] = path.into();
        items.push(unsafe_item);
    }
    assert_eq!(
        connection
            .execute(
                "UPDATE catalog_claims SET canonical_json = ?1 WHERE claim_id = ?2",
                rusqlite::params![claim.to_string(), id],
            )
            .unwrap(),
        1
    );
    for format in ["openapi", "postman", "curl", "bundle"] {
        assert_corrupt_export(&fx, format, None, &format!("unsafe-{format}"));
    }
}

#[test]
fn secret_shaped_claim_evidence_is_refused_by_every_format() {
    let fx = project_with_catalog(TRANSCRIPT);
    edit_claim(&fx, "OrderController.get", |claim| {
        claim["source_evidence"][0]["relative_path"] = "src/password:hunter2hunter2.java".into();
    });
    for format in ["openapi", "postman", "curl", "bundle"] {
        assert_refused(&fx, format, "hunter2");
    }
}

/// Assemble a multi-scope revision from two real scans. Current scan scopes each
/// publish their own revision; this fixture exercises the history port's wider
/// revision representation without inventing operations or claim JSON.
fn add_scope_to_revision(fx: &Fx, component: &str, binding: &str, transcript: &str) -> String {
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
    let analyzer = fx.write_analyzer(transcript);
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

fn claim_transcript(route: &str, symbols: &[String]) -> String {
    use std::fmt::Write as _;

    let mut transcript = TRANSCRIPT.lines().next().unwrap().to_owned();
    transcript.push('\n');
    for (index, symbol) in symbols.iter().enumerate() {
        let line = index + 1;
        let claim = serde_json::json!({
            "type": "claim", "method": "GET", "routeParts": [route], "routeBasis": "literal",
            "handler": symbol, "limitations": [],
            "evidence": {"path": "Handlers.java", "startLine": line, "startColumn": 1,
                         "endLine": line, "endColumn": 11}
        });
        writeln!(transcript, "{claim}").unwrap();
    }
    writeln!(
        transcript,
        "{}",
        serde_json::json!({
            "type": "end", "claims": symbols.len(), "filesScanned": 1, "complete": true,
            "incompleteReasons": []
        })
    )
    .unwrap();
    transcript
}

#[test]
fn export_persisted_path_bearing_handler_symbols_across_formats() {
    use serde_json::json;

    let relative = [
        "src/(admin)/routes.js#list",
        "src/feature routes/route!.ts#GET",
        "src/order routes.js#list",
        "src/routes.js#list",
        "src/routes/[id].ts#GET",
    ];
    let unsafe_symbols = [
        ("/home/export-owner-private/routes.js#list", "export-owner-private"),
        ("src/../traversal-private.js#list", "traversal-private"),
        ("Q:/drive-private.js#list", "drive-private"),
        (r"Q:\backslash-private.js#list", "backslash-private"),
        (r"\\host\share\unc-private.js#list", "unc-private"),
        ("src/routes.js#/embedded-private.js", "embedded-private"),
        ("src/..#terminal-traversal", "terminal-traversal"),
        ("src/handler=/home/prefixed-private.js#list", "prefixed-private"),
        ("src/path Q:/embedded-drive-private.js#list", "embedded-drive-private"),
        ("src/%2e%2e/encoded-traversal-private.js#list", "encoded-traversal-private"),
        ("src/%2Fencoded-absolute-private.js#list", "encoded-absolute-private"),
    ];
    let symbols: Vec<_> = relative
        .into_iter()
        .chain(unsafe_symbols.iter().map(|(symbol, _)| *symbol))
        .map(str::to_owned)
        .collect();
    let fx = fx();
    let src = fx.repo.join("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("Handlers.java"), "// handler\n".repeat(symbols.len())).unwrap();
    let analyzer = fx.write_analyzer(&claim_transcript("/handlers", &symbols));
    let scan = fx.scan(&analyzer);
    assert_eq!(scan.status.code(), Some(0), "{scan:?}");
    let ids: Vec<_> = {
        let connection = rusqlite::Connection::open(fx.database()).unwrap();
        symbols
            .iter()
            .map(|symbol| {
                let (id, claim) = stored_claim(&connection, symbol);
                assert_eq!(claim["handler_symbol"], *symbol);
                uuid::Uuid::from_slice(&id).unwrap().to_string()
            })
            .collect()
    };

    let mut expected = Value::Null;
    for format in ["openapi", "postman", "curl", "bundle"] {
        let out = fx.out_dir(&format!("handler-symbols-{format}"));
        let result = fx.export(&["--format", format, "--output", out.to_str().unwrap()]);
        assert_eq!(result.status.code(), Some(0), "{result:?}");
        assert!(
            json(&result)["omissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|omission| omission["reason"] == "handler_symbol_invalid")
        );
        let files = tree(&out);
        for (name, bytes) in &files {
            let text = std::str::from_utf8(bytes).unwrap();
            for (_, fragment) in unsafe_symbols {
                assert!(!text.contains(fragment), "{format} {name} leaked {fragment}");
            }
        }
        let postman = || {
            let collection: Value =
                serde_json::from_str(&read(&out, "collection.postman.json")).unwrap();
            comment_metadata(collection["item"][0]["request"]["description"].as_str().unwrap())
                .unwrap()
        };
        let curl = || {
            let (_, bytes) =
                files.iter().find(|(name, _)| name.ends_with("-get-handlers.sh")).unwrap();
            comment_metadata(std::str::from_utf8(bytes).unwrap()).unwrap()
        };
        let metadata = match format {
            "openapi" => openapi_metadata(&out, "/handlers", "get"),
            "postman" => postman(),
            "curl" => curl(),
            "bundle" => {
                let block = xtrace_export::canonical::yaml(&json!({"x-xtrace": expected}))
                    .lines()
                    .map(|line| format!("      {line}\n"))
                    .collect::<String>();
                assert!(read(&out, "openapi.yaml").contains(&block));
                assert_eq!(postman(), curl());
                postman()
            }
            _ => unreachable!(),
        };
        if format == "openapi" {
            assert_eq!(metadata["claims_projection"], "available");
            assert_eq!(metadata["claim_count"], ids.len());
            assert_eq!(metadata["handler_conflict"], true);
            assert_eq!(metadata["handler_symbols"], json!(relative));
            let claims = metadata["claims"].as_array().unwrap();
            assert_eq!(claims.len(), ids.len());
            for (index, id) in ids.iter().enumerate() {
                let row = claims.iter().find(|claim| claim["claim_id"] == *id).unwrap();
                let symbol = relative.get(index).map_or(Value::Null, |symbol| json!(symbol));
                assert_eq!(row.get("handler_symbol"), Some(&symbol));
                assert_eq!(row["source_evidence"][0]["relative_path"], "Handlers.java");
                assert_eq!(row["source_evidence"][0]["start_line"], index + 1);
            }
            expected = metadata.clone();
        }
        assert_eq!(metadata, expected, "{format}");
    }
}

#[test]
fn revision_claim_limits_apply_per_operation_in_full_and_selected_exports() {
    use xtrace_domain::ClaimId;
    use xtrace_domain::catalog_discovery::{
        MAX_DISCOVERY_CLAIM_BYTES, MAX_DISCOVERY_RUN_CLAIM_BYTES, MAX_DISCOVERY_RUN_CLAIMS,
    };
    use xtrace_domain::ids::Id as _;

    let fx = fx();
    let src = fx.repo.join("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("Handlers.java"), "// handler\n".repeat(MAX_DISCOVERY_RUN_CLAIMS)).unwrap();
    // Each source line yields a distinct hint. Long symbols make the writer's JSON
    // exceed 4 MiB while the CBOR encoding still fits the run budget.
    let symbol_prefix = "A".repeat(499);
    let symbols: Vec<_> =
        (1..=MAX_DISCOVERY_RUN_CLAIMS).map(|i| format!("Fixture{symbol_prefix}.h{i:04}")).collect();
    let analyzer = fx.write_analyzer(&claim_transcript("/many", &symbols));
    let scan = fx.scan(&analyzer);
    assert_eq!(scan.status.code(), Some(0), "{scan:?}");
    let long_symbol = format!("{}.get", "A".repeat(508));
    let revision = add_scope_to_revision(
        &fx,
        "other-component",
        "default",
        &claim_transcript("/single", std::slice::from_ref(&long_symbol)),
    );

    let full = fx.out_dir("full");
    let result = fx.export(&[
        "--format",
        "openapi",
        "--revision",
        &revision,
        "--output",
        full.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(json(&result)["operationCount"], 2);
    let many = openapi_metadata(&full, "/many", "get");
    assert_eq!(many["claim_count"], MAX_DISCOVERY_RUN_CLAIMS);
    assert_eq!(many["claims"].as_array().unwrap().len(), MAX_DISCOVERY_RUN_CLAIMS);
    let single = openapi_metadata(&full, "/single", "get");
    assert_eq!(single["claim_count"], 1);
    assert_eq!(single["claims"][0]["handler_symbol"], long_symbol);
    for (name, expected) in [("many", &many), ("single", &single)] {
        let selected = fx.out_dir(&format!("selected-{name}"));
        let result = fx.export(&[
            "--format",
            "openapi",
            "--revision",
            &revision,
            "--operations",
            expected["operation_id"].as_str().unwrap(),
            "--output",
            selected.to_str().unwrap(),
        ]);
        assert_eq!(result.status.code(), Some(0), "{result:?}");
        assert_eq!(json(&result)["operationCount"], 1);
        let route = format!("/{name}");
        assert_eq!(&openapi_metadata(&selected, &route, "get"), expected);
        let spec: Value = serde_json::from_str(&read(&selected, "openapi.json")).unwrap();
        assert_eq!(spec["paths"].as_object().unwrap().keys().collect::<Vec<_>>(), [&route]);
    }

    let mut connection = rusqlite::Connection::open(fx.database()).unwrap();
    connection.pragma_update(None, "foreign_keys", true).unwrap();
    let revision_id = uuid::Uuid::parse_str(&revision).unwrap();
    let operation_id = uuid::Uuid::parse_str(many["operation_id"].as_str().unwrap()).unwrap();
    let operation_id = operation_id.as_bytes().as_slice();
    let (canonical_bytes, json_bytes): (usize, usize) = connection
        .query_row(
            "SELECT SUM(length(canonical_bytes)), SUM(length(CAST(canonical_json AS BLOB)))
             FROM catalog_claims WHERE operation_id = ?1",
            [operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(canonical_bytes <= MAX_DISCOVERY_RUN_CLAIM_BYTES, "{canonical_bytes}");
    assert!(json_bytes > MAX_DISCOVERY_RUN_CLAIM_BYTES, "{json_bytes}");
    let extra_id = ClaimId::new().as_uuid();
    let (_, mut extra) = stored_claim(&connection, &symbols[0]);
    extra["claim_hint"] = extra_id.to_string().into();
    let extra = (rebuild_fixture_claim(&extra), extra.to_string());
    assert!(canonical_bytes + extra.0.canonical_bytes().len() <= MAX_DISCOVERY_RUN_CLAIM_BYTES);
    let extra_id = extra_id.as_bytes().as_slice();
    let tx = connection.transaction().unwrap();
    // Add a canonical claim within the byte budget to isolate the count guard.
    assert_eq!(tx.execute(
        "INSERT INTO catalog_claims (claim_id, project_id, operation_id, claim_digest, canonical_bytes, canonical_json, first_revision_id, last_revision_id)
         SELECT ?1, project_id, operation_id, ?2, ?3, ?4, first_revision_id, last_revision_id
         FROM catalog_claims WHERE operation_id = ?5 ORDER BY claim_id LIMIT 1",
        rusqlite::params![extra_id, extra.0.digest().unwrap().as_bytes().as_slice(), extra.0.canonical_bytes(), extra.1, operation_id],
    ).unwrap(), 1);
    assert_eq!(
        tx.execute(
            "INSERT INTO catalog_revision_claims (project_id, revision_id, operation_id, claim_id)
         SELECT project_id, ?1, operation_id, claim_id FROM catalog_claims WHERE claim_id = ?2",
            rusqlite::params![revision_id.as_bytes().as_slice(), extra_id],
        )
        .unwrap(),
        1
    );
    refresh_fixture_version(&tx, revision_id.as_bytes(), operation_id);
    tx.commit().unwrap();
    let assert_rejected = |name: &str| assert_corrupt_export(&fx, "openapi", Some(&revision), name);
    assert_rejected("too-many-claims");

    let tx = connection.transaction().unwrap();
    assert_eq!(
        tx.execute("DELETE FROM catalog_revision_claims WHERE claim_id = ?1", [extra_id]).unwrap(),
        1
    );
    assert_eq!(
        tx.execute("DELETE FROM catalog_claims WHERE claim_id = ?1", [extra_id]).unwrap(),
        1
    );
    refresh_fixture_version(&tx, revision_id.as_bytes(), operation_id);
    tx.commit().unwrap();

    let single_id =
        uuid::Uuid::parse_str(single["claims"][0]["claim_id"].as_str().unwrap()).unwrap();
    let single_id = single_id.as_bytes().as_slice();
    let (valid_canonical, valid_json): (Vec<u8>, String) = connection
        .query_row(
            "SELECT canonical_bytes, canonical_json FROM catalog_claims WHERE claim_id = ?1",
            [single_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let oversized_canonical = vec![0; MAX_DISCOVERY_CLAIM_BYTES + 1];
    let oversized_json = format!("{valid_json:<width$}", width = 16 * 1024 + 1);
    let update_single = |canonical: &[u8], json: &str| {
        assert_eq!(
            connection
                .execute(
                    "UPDATE catalog_claims SET canonical_bytes = ?1, canonical_json = ?2
                     WHERE claim_id = ?3",
                    rusqlite::params![canonical, json, single_id],
                )
                .unwrap(),
            1
        );
    };
    // Bypass the fixture connection's CHECK constraints to exercise the history reader's
    // row guards independently. The padded JSON is still valid JSON.
    connection.pragma_update(None, "ignore_check_constraints", true).unwrap();
    update_single(&oversized_canonical, &valid_json);
    assert_rejected("oversized-canonical-row");
    update_single(&valid_canonical, &oversized_json);
    assert_rejected("oversized-json-row");
    update_single(&valid_canonical, &valid_json);
    connection.pragma_update(None, "ignore_check_constraints", false).unwrap();

    // Grow valid rows past the canonical byte budget while staying within the count and row caps.
    let candidates = {
        let mut statement = connection
            .prepare(
                "SELECT claim_id, length(canonical_bytes), canonical_json
             FROM catalog_claims WHERE operation_id = ?1 ORDER BY claim_id LIMIT 1536",
            )
            .unwrap();
        statement
            .query_map([operation_id], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, usize>(1)?, row.get::<_, String>(2)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    let tx = connection.transaction().unwrap();
    let mut total = canonical_bytes;
    for (id, old_len, json) in candidates {
        let mut value: Value = serde_json::from_str(&json).unwrap();
        let evidence = value["source_evidence"].as_array_mut().unwrap();
        for index in 0..7 {
            evidence.push(serde_json::json!({
                "kind": "runtime_hint",
                "relative_path": format!("{}-{index}.java", "a".repeat(490)),
            }));
        }
        let claim = rebuild_fixture_claim(&value);
        value["source_evidence"] = serde_json::json!(claim.source_evidence());
        replace_claim_payload(
            &tx,
            &id,
            claim.digest().unwrap().as_bytes(),
            claim.canonical_bytes(),
            &value.to_string(),
        );
        total = total - old_len + claim.canonical_bytes().len();
        if total > MAX_DISCOVERY_RUN_CLAIM_BYTES {
            break;
        }
    }
    assert!(total > MAX_DISCOVERY_RUN_CLAIM_BYTES);
    refresh_fixture_version(&tx, revision_id.as_bytes(), operation_id);
    tx.commit().unwrap();
    assert_rejected("too-many-canonical-bytes");
}

#[test]
fn observations_keep_component_and_binding_scope_and_counts_match_each_format() {
    // Each axis must be checked independently. Canonical OpenAPI chooses the
    // unobserved scope first in both cases, so a route-only join fails visibly.
    for (component, binding) in [("a-component", "default"), ("spring-fixture", "a-binding")] {
        let fx = project_with_catalog(TRANSCRIPT);
        let revision = add_scope_to_revision(&fx, component, binding, TRANSCRIPT);
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
fn all_formats_report_unknown_policy_digest_without_revision_provenance() {
    let assert_policy_omission = |doc: &Value| {
        let matching: Vec<_> = doc["omissions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["what"].as_str().unwrap().rsplit(':').next() == Some("policy_digest"))
            .collect();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0]["what"], "policy_digest");
        assert_eq!(matching[0]["reason"], "not_available_in_catalog_view");
    };
    let note = "Omitted policy_digest (not_available_in_catalog_view).";
    let fx = project_with_catalog(TRANSCRIPT);
    let a = fx.out_dir("bundle-a");
    let b = fx.out_dir("bundle-b");
    let preview = fx.export(&["--format", "bundle", "--preview"]);
    assert_eq!(preview.status.code(), Some(0), "{preview:?}");
    assert_policy_omission(&json(&preview));
    let mut results = Vec::new();
    for out in [&a, &b] {
        let result = fx.export(&["--format", "bundle", "--output", out.to_str().unwrap()]);
        assert_eq!(result.status.code(), Some(0), "{result:?}");
        assert_eq!(json(&result)["operationCount"], 3);
        results.push(json(&result));
        assert_policy_omission(results.last().unwrap());
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
    assert_eq!(manifest.get("policy_digest"), Some(&Value::Null));
    assert_policy_omission(&manifest);
    let formats = manifest["formats"].as_array().unwrap();
    assert_eq!(formats.len(), 3);
    for format in formats {
        assert_policy_omission(format);
    }
    assert!(read(&a, "openapi.yaml").contains("policy_digest: null"));
    let openapi = fx.out_dir("openapi-policy");
    let output = fx.export(&["--format", "openapi", "--output", openapi.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_policy_omission(&json(&output));
    let document: Value = serde_json::from_str(&read(&openapi, "openapi.json")).unwrap();
    let metadata = &document["info"]["x-xtrace"];
    assert_eq!(metadata.get("policy_digest"), Some(&Value::Null));
    assert_policy_omission(metadata);
    for (format, path, bundle_path) in [
        ("postman", "collection.postman.json", "collection.postman.json"),
        ("curl", "all.sh", "curl/all.sh"),
    ] {
        let dir = fx.out_dir(format);
        let output = fx.export(&["--format", format, "--output", dir.to_str().unwrap()]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_policy_omission(&json(&output));
        let artifact = read(&dir, path);
        assert_eq!(artifact.matches(note).count(), 1);
        assert_eq!(read(&a, bundle_path), artifact);
    }
    let files = manifest["files"].as_array().unwrap();
    assert_eq!(files.len(), 6);
    assert_eq!(tree(&a).len(), 8, "only payload, manifest and README");
    for file in files {
        let bytes = fs::read(a.join(file["path"].as_str().unwrap())).unwrap();
        assert_eq!(file["bytes"], bytes.len());
        assert_eq!(file["blake3"], blake3::hash(&bytes).to_hex().to_string());
    }
}
