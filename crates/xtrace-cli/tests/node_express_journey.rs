#![cfg(unix)]
#![allow(missing_docs, reason = "integration test symbols are executable fixtures")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "controlled fixture processes and temporary project data are asserted directly"
)]

//! Express 4 and Express 5 journeys: the fixture is started with `xtrace run -- node app.js`, driven
//! over real HTTP, and read back through the recording read API. The fixtures are npm workspace packages, so `npm ci --prefix adapters/node` provides them.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;

struct RunChild(Child);

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

/// What one request must leave behind in the persisted recording.
///
/// The complete recordings are checked for their adapter-observed response status and outcome.
/// With no endpoint observation policy, the supported queries must leave these recordings
/// unmatched with a named reason and expose no observed endpoints. Route templates are checked
/// separately in the in-process journey tests (`express4/5-instrument.test.ts`).
struct Expected {
    target: &'static str,
    /// HTTP status the real fixture answered, checked on the wire.
    status: u16,
    /// Express frame symbols in recorded order (kind prefix, then symbol).
    frames: &'static [&'static str],
}

const COMMON: &[Expected] = &[
    Expected {
        target: "/owners/42?token=QUERY_CANARY",
        status: 200,
        frames: &[
            "enter express.middleware:requestLogger",
            "enter express.handler:showOwner",
            "exit express.handler:showOwner",
            "exit express.middleware:requestLogger",
        ],
    },
    Expected {
        target: "/api/pets/7",
        status: 200,
        frames: &[
            "enter express.middleware:requestLogger",
            "enter express.handler:showPet",
            "exit express.handler:showPet",
            "exit express.middleware:requestLogger",
        ],
    },
    Expected {
        target: "/clinics/9/vets/3",
        status: 200,
        frames: &[
            "enter express.middleware:requestLogger",
            "enter express.handler:showVet",
            "exit express.handler:showVet",
            "exit express.middleware:requestLogger",
        ],
    },
    Expected {
        target: "/boom",
        status: 500,
        frames: &[
            "enter express.middleware:requestLogger",
            "enter express.handler:explode",
            "throw express.handler:explode",
            "enter express.error_handler:appErrorHandler",
            "exit express.error_handler:appErrorHandler",
            "exit express.middleware:requestLogger",
        ],
    },
    Expected {
        target: "/missing",
        status: 404,
        frames: &[
            "enter express.middleware:requestLogger",
            "exit express.middleware:requestLogger",
        ],
    },
    // A sub-application mount is not visible to the Layer patch: the route stays unresolved
    // (honest) rather than being guessed as `/ping`.
    Expected {
        target: "/sub/ping",
        status: 200,
        frames: &[
            "enter express.middleware:requestLogger",
            "enter express.middleware:mounted_app",
            "enter express.handler:pingSub",
            "exit express.handler:pingSub",
            "exit express.middleware:mounted_app",
            "exit express.middleware:requestLogger",
        ],
    },
];

/// The shutdown request. The recording that is last before the process exits is not asserted
/// frame-for-frame: probes show its tail (everything after the handler frame) is not persisted and
/// the recording reads `partial`, an exit-time flush gap reported in the lane report. Here it only
/// has to exist and begin with the same Express frames.
const SENTINEL: &str = "/done";
const SENTINEL_PREFIX: &[&str] =
    &["enter express.middleware:requestLogger", "enter express.handler:finish"];

#[test]
fn express4_requests_persist_route_middleware_handler_and_error_frames() {
    journey("express4-app");
}

#[test]
fn express5_requests_persist_route_middleware_handler_and_error_frames() {
    journey("express5-app");
}

fn journey(fixture: &str) {
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
        "run `npm run build --prefix adapters/node` before this test"
    );
    let app = workspace.join("adapters/node/examples").join(fixture).join("app.js");
    let express_json = app.parent().unwrap().join("node_modules/express/package.json");
    let hoisted_json = workspace.join("adapters/node/node_modules/express/package.json");
    assert!(
        express_json.is_file() || hoisted_json.is_file(),
        "run `npm ci --prefix adapters/node` before this test (fixture {fixture} has no express)"
    );

    let mut child = RunChild(
        cli()
            .args(["run", "--project-dir"])
            .arg(&repo)
            .args(["--node-adapter"])
            .arg(&adapter_dist)
            .args(["--node-mode", "cjs", "--", "node", "--no-warnings"])
            .arg(&app)
            .current_dir(app.parent().expect("fixture directory"))
            .env("XTRACE_DATA_HOME", &data_home)
            .env("APP_PORT", "0")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start supervised Express app"),
    );
    let (line_sender, line_receiver) = mpsc::channel();
    let stdout = child.0.stdout.take().expect("stdout");
    let stdout_reader = thread::spawn(move || {
        let mut reader = std::io::BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Err(_) => {
                    let _ = line_sender.send(Err(()));
                    break;
                }
                Ok(_) => {
                    let _ = line_sender.send(Ok(line));
                }
            }
        }
    });
    let stderr = child.0.stderr.take().expect("stderr");
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        std::io::BufReader::new(stderr).read_to_end(&mut bytes).expect("drain stderr");
        bytes
    });
    // Both lines belong to the same listening child. Selecting the port in the parent would
    // release its reservation before Express binds, allowing another server to take that port.
    let readiness_deadline = Instant::now() + Duration::from_secs(20);
    let ready = readiness_line(&line_receiver, readiness_deadline);
    assert!(ready.trim() == "EXPRESS_READY", "Express readiness failure: InvalidMarker");
    let address = readiness_line(&line_receiver, readiness_deadline);
    let port = address
        .trim()
        .strip_prefix("EXPRESS_PORT=")
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .expect("Express readiness failure: InvalidPort");

    for expected in COMMON {
        let status = get(port, expected.target);
        assert_eq!(status, expected.status, "status of {}", expected.target);
    }
    assert_eq!(get(port, SENTINEL), 200, "status of the shutdown request");
    let closed = line_receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("server close")
        .expect("read server close");
    assert_eq!(closed.trim(), "EXPRESS_SERVER_CLOSED");
    let status = wait_for_child(&mut child.0, Duration::from_secs(20));
    assert!(status.success(), "Express run failed with {status}");
    stdout_reader.join().expect("join stdout reader");
    let stderr_text =
        String::from_utf8_lossy(&stderr_reader.join().expect("join stderr reader")).into_owned();
    for canary in ["QUERY_CANARY", "SECRET_CANARY"] {
        assert!(!stderr_text.contains(canary), "{canary} reached stderr");
    }

    let list = list_recordings(&repo, &data_home);
    let recordings = list["recordings"].as_array().expect("recordings");
    assert_eq!(recordings.len(), COMMON.len() + 1, "exactly one recording per request: {list}");

    let unmatched = endpoint_projection(&repo, &data_home, &["recording", "list", "--unmatched"]);
    let unmatched_rows = unmatched["items"].as_array().expect("unmatched recording items");
    assert!(
        unmatched.get("nextCursor") == Some(&Value::Null),
        "unmatched recording page must be complete"
    );
    assert!(
        unmatched_rows.len() == recordings.len(),
        "every default Node recording must remain unmatched"
    );
    let recorded_ids: BTreeSet<_> =
        recordings.iter().map(|row| row["recording_id"].as_str().expect("recording id")).collect();
    let unmatched_ids: BTreeSet<_> = unmatched_rows
        .iter()
        .map(|row| row["recordingId"].as_str().expect("unmatched recording id"))
        .collect();
    assert!(recorded_ids.len() == recordings.len(), "recording list identities must be unique");
    assert!(
        unmatched_ids.len() == unmatched_rows.len(),
        "unmatched recording identities must be unique"
    );
    assert!(recorded_ids == unmatched_ids, "unmatched recording identities must match the list");
    for row in unmatched_rows {
        assert!(
            row.get("operationId") == Some(&Value::Null),
            "default Node recording must not claim an operation"
        );
        assert!(
            row.get("observationPolicy") == Some(&Value::Null),
            "default Node recording must not claim a policy"
        );
        assert!(
            row["unmatchedReason"] == "observation_policy_missing",
            "default Node recording must name the missing endpoint policy"
        );
    }
    let endpoints = endpoint_projection(&repo, &data_home, &["endpoint", "list"]);
    assert!(
        endpoints["items"].as_array().expect("observed endpoint items").is_empty(),
        "default Node capture must not claim an observed endpoint"
    );
    assert!(
        endpoints.get("nextCursor") == Some(&Value::Null),
        "empty observed endpoint page must be complete"
    );

    let mut observed: Vec<(String, Value, Vec<String>)> = Vec::new();
    let mut outcomes = BTreeMap::new();
    for metadata in recordings {
        let id = metadata["recording_id"].as_str().expect("recording id");
        let detail = show_recording(&repo, &data_home, id);
        outcomes.insert(id.to_owned(), detail["outcome"].clone());
        let completion = detail["completion"].clone();
        let events = detail["events"].as_array().expect("events");
        let roots = events
            .iter()
            .filter(|event| {
                event["symbol"] == "node:http.Server.request"
                    && event["kind"] == "recording_event_kind:frame_enter"
            })
            .count();
        assert_eq!(roots, 1, "exactly one root frame per request: {detail}");
        let frames: Vec<String> = events
            .iter()
            .filter_map(|event| {
                let symbol = event["symbol"].as_str()?;
                if !symbol.starts_with("express.") {
                    return None;
                }
                let kind = match event["kind"].as_str()? {
                    "recording_event_kind:frame_enter" => "enter",
                    "recording_event_kind:frame_exit" => "exit",
                    "recording_event_kind:frame_throw" => "throw",
                    _ => return None,
                };
                Some(format!("{kind} {symbol}"))
            })
            .collect();
        // Frames nest as the calls nest: the first Express frame hangs off the root, and each
        // handler frame hangs off the middleware frame that called `next()`.
        let root_id = events[0]["event_id"].as_str().expect("root event id");
        let first_express = events
            .iter()
            .find(|event| event["symbol"].as_str().is_some_and(|s| s.starts_with("express.")))
            .expect("an Express frame");
        assert_eq!(
            first_express["parent_event_id"], root_id,
            "middleware hangs off the root: {detail}"
        );
        observed.push((id.to_owned(), completion, frames));
    }

    for expected in COMMON {
        let position = observed
            .iter()
            .position(|(_, completion, frames)| {
                *completion == "complete"
                    && frames.iter().map(String::as_str).eq(expected.frames.iter().copied())
            })
            .unwrap_or_else(|| panic!("no recording matches {} in {observed:#?}", expected.target));
        let (id, _, _) = observed.remove(position);
        let outcome = outcomes.get(&id).expect("recording outcome projection");
        assert!(
            outcome["kind"] == "responded",
            "complete Express response outcome must be observed"
        );
        assert!(
            outcome["httpStatus"].as_u64() == Some(u64::from(expected.status)),
            "persisted response status must match the fixture response"
        );
    }
    assert_eq!(observed.len(), 1, "only the shutdown request is left: {observed:#?}");
    assert!(
        observed[0]
            .2
            .iter()
            .map(String::as_str)
            .take(SENTINEL_PREFIX.len())
            .eq(SENTINEL_PREFIX.iter().copied()),
        "the shutdown request starts with the Express frames: {observed:#?}"
    );
}

fn get(port: u16, target: &str) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(10))).expect("read timeout");
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: bearer-PRIVATE\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).expect("send request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    let text = String::from_utf8_lossy(&response);
    text.split_whitespace().nth(1).and_then(|code| code.parse().ok()).expect("status line")
}

fn show_recording(repo: &Path, data_home: &Path, id: &str) -> Value {
    let output = cli()
        .args(["recording", "show", "--project-dir"])
        .arg(repo)
        .arg(id)
        .env("XTRACE_DATA_HOME", data_home)
        .output()
        .expect("recording show");
    assert!(output.status.success(), "recording show failed: {}", diagnostic(&output));
    for canary in ["QUERY_CANARY", "SECRET_CANARY", "bearer-PRIVATE"] {
        assert!(
            !output.stdout.windows(canary.len()).any(|window| window == canary.as_bytes()),
            "{canary} reached the read projection"
        );
    }
    serde_json::from_slice(&output.stdout).expect("recording detail JSON")
}

fn list_recordings(repo: &Path, data_home: &Path) -> Value {
    let output = cli()
        .args(["recording", "list", "--project-dir"])
        .arg(repo)
        .args(["--limit", "50"])
        .env("XTRACE_DATA_HOME", data_home)
        .output()
        .expect("recording list");
    assert!(output.status.success(), "recording list failed: {}", diagnostic(&output));
    serde_json::from_slice(&output.stdout).expect("recording list JSON")
}

fn endpoint_projection(repo: &Path, data_home: &Path, command: &[&str]) -> Value {
    let output = cli()
        .args(command)
        .arg("--project-dir")
        .arg(repo)
        .args(["--limit", "50"])
        .env("XTRACE_DATA_HOME", data_home)
        .output()
        .expect("query endpoint observation projection");
    assert!(output.status.success(), "endpoint observation query failed");
    for canary in ["QUERY_CANARY", "SECRET_CANARY", "bearer-PRIVATE"] {
        assert!(
            !output.stdout.windows(canary.len()).any(|window| window == canary.as_bytes()),
            "private canary reached endpoint observation projection"
        );
    }
    serde_json::from_slice(&output.stdout).expect("endpoint observation JSON")
}

fn temp_root() -> TempDir {
    let base = std::env::temp_dir().canonicalize().expect("canonical temporary root");
    tempfile::Builder::new()
        .prefix("xtrace express ")
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir_in(base)
        .expect("temporary root")
}

fn readiness_line(receiver: &mpsc::Receiver<Result<String, ()>>, deadline: Instant) -> String {
    // Report only fixed categories: child output can contain private fixture or runtime data.
    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(line)) => line,
        Ok(Err(())) => panic!("Express readiness failure: ReadError"),
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("Express readiness failure: Timeout"),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("Express readiness failure: Disconnected");
        }
    }
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll xtrace child") {
            return status;
        }
        assert!(Instant::now() < deadline, "xtrace Express run exceeded its deadline");
        thread::sleep(Duration::from_millis(10));
    }
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_xtrace"))
}

fn diagnostic(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
