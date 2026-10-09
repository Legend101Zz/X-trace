#![cfg(unix)]
#![allow(missing_docs, reason = "integration test symbols are executable fixtures")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "controlled fixture processes and temporary project data are asserted directly"
)]

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;

struct RunChild(Child);

impl std::ops::Deref for RunChild {
    type Target = Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RunChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for RunChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            if let Ok(pid) = i32::try_from(self.0.id()) {
                if let Some(pid) = rustix::process::Pid::from_raw(pid) {
                    let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
                }
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            while self.0.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
}

fn temp_root() -> TempDir {
    let base = std::env::temp_dir().canonicalize().expect("canonical temporary root");
    tempfile::Builder::new()
        .prefix("xtrace node run ")
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir_in(base)
        .expect("temporary root")
}

#[test]
fn direct_node_http_run_persists_private_concurrent_cjs_and_esm_recordings_across_reopen() {
    let root = temp_root();
    let repo = root.path().join("repository with spaces");
    let data_home = root.path().join("data home");
    std::fs::create_dir_all(&repo).expect("create repository");
    let init = cli()
        .args(["init", "--project-dir"])
        .arg(&repo)
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("initialize project");
    assert!(init.status.success(), "init failed: {}", diagnostic(&init));

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let adapter_dist = workspace.join("adapters/node/packages/adapter-core/dist");
    assert!(
        adapter_dist.join("manifest.sha256").is_file(),
        "run `npm run build:core --offline` before this test"
    );

    run_application(&repo, &data_home, &adapter_dist, "cjs");
    let first = list_recordings(&repo, &data_home);
    assert_eq!(first["recordings"].as_array().expect("recordings").len(), 2);
    assert_recording_evidence(&first, &repo, &data_home);

    // A second independent xtrace run proves the previous daemon/bootstrap and
    // session were shut down cleanly while the recording store remains readable.
    run_application(&repo, &data_home, &adapter_dist, "esm");
    let reopened = list_recordings(&repo, &data_home);
    assert_eq!(reopened["recordings"].as_array().expect("recordings").len(), 4);
    assert_recording_evidence(&reopened, &repo, &data_home);
}

/// `--node-mode auto` injects both the `--require` and `--import` preloads; capture must still start
/// once, so each request yields exactly one root whether the entry is CommonJS or an ES module.
#[test]
fn auto_mode_records_cjs_and_esm_entries_once_each() {
    let root = temp_root();
    let repo = root.path().join("repository");
    let data_home = root.path().join("data");
    std::fs::create_dir_all(&repo).expect("create repository");
    let init = cli()
        .args(["init", "--project-dir"])
        .arg(&repo)
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("initialize project");
    assert!(init.status.success(), "init failed: {}", diagnostic(&init));
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let adapter_dist = workspace.join("adapters/node/packages/adapter-core/dist");
    assert!(
        adapter_dist.join("manifest.sha256").is_file(),
        "run `npm run build:core --offline` before this test"
    );

    run_application_as(&repo, &data_home, &adapter_dist, "auto", "cjs");
    let first = list_recordings(&repo, &data_home);
    assert_eq!(first["recordings"].as_array().expect("recordings").len(), 2);
    assert_recording_evidence(&first, &repo, &data_home);
    run_application_as(&repo, &data_home, &adapter_dist, "auto", "esm");
    let second = list_recordings(&repo, &data_home);
    assert_eq!(second["recordings"].as_array().expect("recordings").len(), 4);
    assert_recording_evidence(&second, &repo, &data_home);
}

#[test]
fn direct_node_run_preserves_application_exit_code() {
    let root = temp_root();
    let repo = root.path().join("repository");
    let data_home = root.path().join("data");
    std::fs::create_dir_all(&repo).expect("create repository");
    let init = cli()
        .args(["init", "--project-dir"])
        .arg(&repo)
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("initialize project");
    assert!(init.status.success(), "init failed: {}", diagnostic(&init));

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let adapter_dist = workspace.join("adapters/node/packages/adapter-core/dist");
    let app = root.path().join("exit-code.cjs");
    std::fs::write(&app, "process.exit(37);\n").expect("write Node exit fixture");
    let output = cli()
        .args(["run", "--project-dir"])
        .arg(&repo)
        .args(["--node-adapter"])
        .arg(adapter_dist)
        .args(["--node-mode", "cjs", "--", "node"])
        .arg(app)
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("run direct Node child");
    assert_eq!(
        output.status.code(),
        Some(37),
        "application exit code changed: {}",
        diagnostic(&output)
    );
}

fn run_application(repo: &Path, data_home: &Path, adapter_dist: &Path, mode: &str) {
    run_application_as(repo, data_home, adapter_dist, mode, mode);
}

/// `launch_mode` is the `--node-mode` value; `entry` is the module system of the application file.
fn run_application_as(
    repo: &Path,
    data_home: &Path,
    adapter_dist: &Path,
    launch_mode: &str,
    entry: &str,
) {
    let mode = entry;
    let root = repo.parent().expect("temporary root");
    let extension = if mode == "cjs" { "cjs" } else { "mjs" };
    let app = root.join(format!("http-app-{mode}.{extension}"));
    let source = if mode == "cjs" {
        r#"const http = require('node:http');
let completed = 0;
const server = http.createServer(async (_request, response) => {
  await new Promise((resolve) => setTimeout(resolve, 12));
  response.statusCode = 201;
  response.end('accepted');
  completed += 1;
  if (completed === 2) server.close(() => console.log('NODE_HTTP_SERVER_CLOSED'));
});
server.listen(Number(process.env.APP_PORT), '127.0.0.1', () => console.log('NODE_HTTP_READY'));
"#
    } else {
        r#"import http from 'node:http';
let completed = 0;
const server = http.createServer(async (_request, response) => {
  await new Promise((resolve) => setTimeout(resolve, 12));
  response.statusCode = 201;
  response.end('accepted');
  completed += 1;
  if (completed === 2) server.close(() => console.log('NODE_HTTP_SERVER_CLOSED'));
});
server.listen(Number(process.env.APP_PORT), '127.0.0.1', () => console.log('NODE_HTTP_READY'));
"#
    };
    std::fs::write(&app, source).expect("write direct Node HTTP app");
    let port = free_port();
    let mut child = RunChild(
        cli()
            .args(["run", "--project-dir"])
            .arg(repo)
            .args(["--node-adapter"])
            .arg(adapter_dist)
            .args(["--node-mode", launch_mode, "--", "node", "--no-warnings"])
            .arg(&app)
            .env("XTRACE_DATA_HOME", data_home)
            .env("APP_PORT", port.to_string())
            .env("NODE_OPTIONS", "--trace-warnings")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start supervised direct Node app"),
    );
    let (line_sender, line_receiver) = mpsc::channel();
    let stdout = child.stdout.take().expect("xtrace stdout");
    let stdout_reader = thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let _ = line_sender.send(line);
                }
            }
        }
    });
    let stderr = child.stderr.take().expect("xtrace stderr");
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        std::io::BufReader::new(stderr).read_to_end(&mut bytes).expect("drain xtrace stderr");
        bytes
    });
    let ready = line_receiver.recv_timeout(Duration::from_secs(10)).expect("Node app readiness");
    assert_eq!(ready.trim(), "NODE_HTTP_READY", "unexpected child output: {ready}");
    let canary = format!("NODE_PRIVATE_CANARY_{launch_mode}_{mode}_4a7");
    let first = canary.clone();
    let second = canary.clone();
    let address = format!("127.0.0.1:{port}");
    let one = thread::spawn(move || post(&address, "/one?secret=QUERY_CANARY", &first));
    let address = format!("127.0.0.1:{port}");
    let two = thread::spawn(move || post(&address, "/two?secret=QUERY_CANARY", &second));
    assert!(one.join().expect("join first request"));
    assert!(two.join().expect("join second request"));
    let closed = line_receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("Node HTTP server close callback");
    assert_eq!(closed.trim(), "NODE_HTTP_SERVER_CLOSED");
    let status = wait_for_child(&mut child, Duration::from_secs(15));
    assert!(status.success(), "Node run failed with {status}");
    stdout_reader.join().expect("join xtrace stdout reader");
    for line in line_receiver.try_iter() {
        assert!(!line.contains(&canary), "request data leaked to stdout");
        assert!(!line.contains("QUERY_CANARY"), "request target leaked to stdout");
    }
    let stderr = stderr_reader.join().expect("join xtrace stderr reader");
    assert!(!String::from_utf8_lossy(&stderr).contains(&canary), "request data leaked to stderr");
    assert!(
        !String::from_utf8_lossy(&stderr).contains("QUERY_CANARY"),
        "request target leaked to stderr"
    );
}

fn post(address: &str, target: &str, canary: &str) -> bool {
    let mut stream = match TcpStream::connect(address) {
        Ok(stream) => stream,
        Err(_) => return false,
    };
    let body = format!("body={canary}");
    let request = format!(
        "POST {target} HTTP/1.1\r\nHost: {address}\r\nAuthorization: bearer-{canary}\r\nX-Private: {canary}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut response = Vec::new();
    if stream.read_to_end(&mut response).is_err() {
        return false;
    }
    response.starts_with(b"HTTP/1.1 201")
        && !response.windows(canary.len()).any(|window| window == canary.as_bytes())
}

fn list_recordings(repo: &Path, data_home: &Path) -> Value {
    let output = cli()
        .args(["recording", "list", "--project-dir"])
        .arg(repo)
        .args(["--limit", "10"])
        .env("XTRACE_DATA_HOME", data_home)
        .output()
        .expect("query persisted recording list");
    assert!(output.status.success(), "recording list failed: {}", diagnostic(&output));
    serde_json::from_slice(&output.stdout).expect("recording list JSON")
}

fn assert_recording_evidence(page: &Value, repo: &Path, data_home: &Path) {
    for metadata in page["recordings"].as_array().expect("recordings") {
        let id = metadata["recording_id"].as_str().expect("recording ID");
        let output = cli()
            .args(["recording", "show", "--project-dir"])
            .arg(repo)
            .arg(id)
            .env("XTRACE_DATA_HOME", data_home)
            .output()
            .expect("query persisted Node recording");
        assert!(output.status.success(), "recording show failed: {}", diagnostic(&output));
        let detail: Value = serde_json::from_slice(&output.stdout).expect("recording detail JSON");
        let events = detail["events"].as_array().expect("persisted events");
        assert!(
            events.iter().any(|event| event["symbol"] == "node:http.Server.request"),
            "missing real HTTP application callback evidence"
        );
        assert!(
            events.iter().any(|event| event["symbol"] == "node:http.response.finish"),
            "missing observed response finish"
        );
        // One root per request: the application callback frame is entered and exited exactly once,
        // events are contiguous from sequence 2, and the response hangs off the root.
        let kinds: Vec<(&str, &str)> = events
            .iter()
            .map(|event| {
                (
                    event["kind"].as_str().expect("event kind"),
                    event["symbol"].as_str().expect("event symbol"),
                )
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("recording_event_kind:frame_enter", "node:http.Server.request"),
                ("recording_event_kind:frame_exit", "node:http.Server.request"),
                ("recording_event_kind:response", "node:http.response.finish"),
            ],
            "exactly one root frame and one response per request"
        );
        let sequences: Vec<&str> =
            events.iter().map(|event| event["sequence"].as_str().expect("sequence")).collect();
        assert_eq!(sequences, ["2", "3", "4"]);
        let root_id = events[0]["event_id"].as_str().expect("root event id");
        assert_eq!(events[2]["parent_event_id"], root_id, "response is a child of the root frame");
        assert!(
            !events.iter().any(|event| event["symbol"]
                .as_str()
                .is_some_and(|s| s.contains("one") || s.contains("two"))),
            "request path must not appear in event symbols"
        );
        // `unavailable.completion` reports whether durable terminal evidence exists; it is no
        // HTTP outcome projection. The recording must carry verified completion evidence.
        assert_eq!(detail["completion"], "complete", "terminal evidence must be verified");
        assert_eq!(detail["unavailable"]["completion"], "available");
        assert_eq!(detail["unavailable"]["values"], "unavailable");
        for canary in ["NODE_PRIVATE_CANARY", "QUERY_CANARY", "bearer-", "Content-Type"] {
            assert!(
                !output.stdout.windows(canary.len()).any(|window| window == canary.as_bytes()),
                "sensitive canary {canary} reached the read projection"
            );
        }
    }
}

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("bind ephemeral local port")
        .local_addr()
        .expect("port address")
        .port()
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll xtrace child") {
            return status;
        }
        if Instant::now() >= deadline {
            if let Ok(pid) = i32::try_from(child.id()) {
                if let Some(pid) = rustix::process::Pid::from_raw(pid) {
                    if let Err(error) =
                        rustix::process::kill_process(pid, rustix::process::Signal::TERM)
                    {
                        assert_eq!(
                            error,
                            rustix::io::Errno::SRCH,
                            "send SIGTERM to timed out supervisor"
                        );
                    }
                }
            }
            let grace_deadline = Instant::now() + Duration::from_secs(12);
            while child.try_wait().expect("poll supervisor after SIGTERM").is_none()
                && Instant::now() < grace_deadline
            {
                thread::sleep(Duration::from_millis(10));
            }
            if child.try_wait().expect("poll supervisor before SIGKILL").is_none() {
                child.kill().expect("kill timed out supervisor");
                child.wait().expect("reap timed out supervisor");
            }
            panic!("xtrace Node run exceeded its deadline");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_xtrace"))
}
fn diagnostic(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
