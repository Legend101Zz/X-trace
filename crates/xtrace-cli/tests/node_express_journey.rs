#![cfg(unix)]
#![allow(missing_docs, reason = "integration test symbols are executable fixtures")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "controlled fixture processes and temporary project data are asserted directly"
)]

//! Express 4 and Express 5 journeys: the fixture is started with `xtrace run -- node app.js`, driven
//! over real HTTP, and read back through the recording read API plus the route stored with each
//! recording. The fixtures are npm workspace packages, so `npm ci --prefix adapters/node` provides them.

use std::io::{BufRead as _, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::Connection;
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

/// What one request must leave behind.
struct Expected {
    target: &'static str,
    status: u16,
    /// Route template the recording carries; empty when the request matched no route.
    route: &'static str,
    /// Handler-level frame symbols in recorded order (kind prefix, then symbol).
    frames: &'static [&'static str],
}

const COMMON: &[Expected] = &[
    Expected {
        target: "/owners/42?token=QUERY_CANARY",
        status: 200,
        route: "/owners/:id",
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
        route: "/api/pets/:petId",
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
        route: "/clinics/:clinicId/vets/:vetId",
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
        route: "/boom",
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
        route: "",
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
        route: "",
        frames: &[
            "enter express.middleware:requestLogger",
            "enter express.handler:pingSub",
            "exit express.handler:pingSub",
            "exit express.middleware:requestLogger",
        ],
    },
    Expected {
        target: "/done",
        status: 200,
        route: "/done",
        frames: &[
            "enter express.middleware:requestLogger",
            "enter express.handler:finish",
            "exit express.handler:finish",
            "exit express.middleware:requestLogger",
        ],
    },
];

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
    let project_id =
        serde_json::from_slice::<Value>(&init.stdout).expect("init JSON")["project_id"]
            .as_str()
            .expect("project id")
            .to_owned();

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

    let port = free_port();
    let mut child = RunChild(
        cli()
            .args(["run", "--project-dir"])
            .arg(&repo)
            .args(["--node-adapter"])
            .arg(&adapter_dist)
            .args(["--node-mode", "cjs", "--", "node", "--no-warnings"])
            .arg(&app)
            .env("XTRACE_DATA_HOME", &data_home)
            .env("APP_PORT", port.to_string())
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
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let _ = line_sender.send(line);
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
    let ready = line_receiver.recv_timeout(Duration::from_secs(20)).expect("Express readiness");
    assert_eq!(ready.trim(), "EXPRESS_READY", "unexpected child output: {ready}");

    for expected in COMMON {
        let status = get(port, expected.target);
        assert_eq!(status, expected.status, "status of {}", expected.target);
    }
    let closed = line_receiver.recv_timeout(Duration::from_secs(10)).expect("server close");
    assert_eq!(closed.trim(), "EXPRESS_SERVER_CLOSED");
    let status = wait_for_child(&mut child.0, Duration::from_secs(20));
    assert!(status.success(), "Express run failed with {status}");
    stdout_reader.join().expect("join stdout reader");
    let stderr_text =
        String::from_utf8_lossy(&stderr_reader.join().expect("join stderr reader")).into_owned();
    for canary in ["QUERY_CANARY", "SECRET_CANARY"] {
        assert!(!stderr_text.contains(canary), "{canary} reached stderr");
    }

    let project_root = data_home.join("projects").join(&project_id);
    let list = list_recordings(&repo, &data_home);
    let recordings = list["recordings"].as_array().expect("recordings");
    assert_eq!(recordings.len(), COMMON.len(), "exactly one recording per request: {list}");

    let database =
        Connection::open(project_root.join("metadata.sqlite3")).expect("metadata database");
    let mut observed: Vec<(String, u64, String, Vec<String>)> = Vec::new();
    for metadata in recordings {
        let id = metadata["recording_id"].as_str().expect("recording id");
        let detail = show_recording(&repo, &data_home, id);
        assert_eq!(
            detail["completion"], "complete",
            "terminal evidence must be verified: {detail}"
        );
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
        let status = outcome_status(&detail);
        let route = stored_route(&database, id);
        observed.push((route, status, id.to_owned(), frames));
    }

    for expected in COMMON {
        let position = observed
            .iter()
            .position(|(route, status, _, frames)| {
                route == expected.route
                    && *status == u64::from(expected.status)
                    && frames.iter().map(String::as_str).eq(expected.frames.iter().copied())
            })
            .unwrap_or_else(|| panic!("no recording matches {} in {observed:#?}", expected.target));
        observed.remove(position);
    }
    assert!(observed.is_empty(), "unexpected extra recordings: {observed:#?}");
}

/// The route stored with the recording's endpoint observation (the template carried on its start).
fn stored_route(database: &Connection, recording_id: &str) -> String {
    let wanted = recording_id.replace('-', "").to_lowercase();
    let mut statement = database
        .prepare(
            "SELECT lower(hex(recording_id)), route_template FROM recording_endpoint_observations",
        )
        .expect("prepare route query");
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)))
        .expect("query routes")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect routes");
    rows.into_iter()
        .find(|(id, _)| *id == wanted)
        .unwrap_or_else(|| panic!("no endpoint observation for {recording_id}"))
        .1
        .unwrap_or_default()
}

fn outcome_status(detail: &Value) -> u64 {
    let outcome = &detail["outcome"];
    assert_eq!(outcome["kind"], "responded", "Express handled every request itself: {detail}");
    outcome["http_status"].as_u64().or_else(|| outcome["httpStatus"].as_u64()).expect("http status")
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

fn temp_root() -> TempDir {
    let base = std::env::temp_dir().canonicalize().expect("canonical temporary root");
    tempfile::Builder::new()
        .prefix("xtrace express ")
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir_in(base)
        .expect("temporary root")
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
