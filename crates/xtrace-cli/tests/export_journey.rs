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
        fs::write(&path, "#!/bin/sh\ncat \"$(dirname \"$0\")/transcript.jsonl\"\n")
            .expect("analyzer");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    fn scan(&self, analyzer: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["scan", "--project-dir"])
            .arg(&self.repo)
            .arg("--source")
            .arg(self.repo.join("src"))
            .args([
                "--framework",
                "spring-mvc",
                "--application-component",
                "spring-fixture",
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
        vec!["--format", "openapi", "--operations", "no-such-operation", "--output", o],
    ] {
        let output = fx.export(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(!out.exists(), "{args:?} created output");
    }
    // 9: bundle is not built yet.
    let bundle = fx.export(&["--format", "bundle", "--output", o]);
    assert_eq!(bundle.status.code(), Some(9), "{bundle:?}");
    assert!(!out.exists());
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
    // 2: no catalog revision yet.
    let empty = self::fx();
    let none = empty.export(&["--format", "openapi", "--preview"]);
    assert_eq!(none.status.code(), Some(2), "{none:?}");
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
    let output =
        fx.export(&["--format", "openapi", "--operations", id, "--output", out.to_str().unwrap()]);
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
fn secret_shaped_handler_text_is_refused_by_openapi_with_the_policy_exit_code() {
    let leaky = TRANSCRIPT.replace("OrderController.get", "password=hunter2hunter2");
    let fx = project_with_catalog(&leaky);
    assert_refused(&fx, "openapi", "hunter2");
}

#[test]
fn secret_shaped_route_text_is_refused_by_every_format() {
    let leaky = TRANSCRIPT.replace("\"/{id}\"", "\"/keys/sk-abcdefghijklmnopqrstuvwxyz0123\"");
    let fx = project_with_catalog(&leaky);
    for format in ["openapi", "postman", "curl"] {
        assert_refused(&fx, format, "abcdefghijklmnopqrstuvwxyz0123");
    }
}
