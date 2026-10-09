//! Real-process journeys for `xtrace record`, `stop` and `restart`.
//!
//! Every test starts the actual `xtrace` binary and a detached daemon. PIDs that the tests signal
//! were obtained from the CLI's own documents or from children the test spawned; nothing is ever
//! signalled by name or pattern.

#![cfg(unix)]
#![allow(missing_docs, reason = "integration test symbols are executable fixtures")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "end-to-end test asserts on controlled local process and fixture state"
)]

use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use prost::Message as _;
use serde_json::Value;
use tempfile::TempDir;
use xtrace_application::recording::{
    AcceptedRecordingEvent, BeginRecording, PersistRecordingSegment, RecordingPersistencePort as _,
};
use xtrace_domain::{ProjectId, RecordingId, RuntimeSessionId, WallTime};
use xtrace_protocol::generated::agent::RecordingEvent;
use xtrace_protocol::xtf::XtfEventEnvelope;
use xtrace_store::{OpenOptions, SqliteRecordingPersistence, SqliteStore};

struct Fixture {
    root: TempDir,
    repo: PathBuf,
    data_home: PathBuf,
    project_id: String,
    // PIDs from CLI documents, kept for assertions only; cleanup goes through the product's
    // identity-checked `xtrace stop`, never a raw signal.
    daemons: std::sync::Mutex<Vec<u32>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Best effort cleanup of a daemon this test started via `xtrace record`: the product's
        // own stop verifies process identity before signalling, so a stale or reused PID is
        // never touched. Result ignored (already stopped is fine).
        let _ = Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["stop", "--project-dir"])
            .arg(&self.repo)
            .env("XTRACE_DATA_HOME", &self.data_home)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Kills and reaps a child this test spawned itself if an assertion unwinds first.
struct ChildGuard(Option<std::process::Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn fixture() -> Fixture {
    let base = std::env::temp_dir().canonicalize().expect("canonical temp base");
    let root = tempfile::Builder::new()
        .prefix("xt-life-")
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir_in(base)
        .expect("temporary root");
    let repo = root.path().join("repo");
    let data_home = root.path().join("data");
    std::fs::create_dir_all(&repo).expect("repo");
    let init = Command::new(env!("CARGO_BIN_EXE_xtrace"))
        .args(["init", "--project-dir"])
        .arg(&repo)
        .env("XTRACE_DATA_HOME", &data_home)
        .output()
        .expect("init");
    assert!(init.status.success(), "init: {}", String::from_utf8_lossy(&init.stderr));
    let doc: Value = serde_json::from_slice(&init.stdout).expect("init JSON");
    let project_id = doc["project_id"].as_str().expect("project_id").to_string();
    Fixture { root, repo, data_home, project_id, daemons: std::sync::Mutex::new(Vec::new()) }
}

impl Fixture {
    fn xtrace(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(args)
            .arg("--project-dir")
            .arg(&self.repo)
            .env("XTRACE_DATA_HOME", &self.data_home)
            .stdin(Stdio::null())
            .output()
            .expect("run xtrace")
    }

    fn ok_json(&self, args: &[&str]) -> Value {
        let out = self.xtrace(args);
        assert!(
            out.status.success(),
            "{args:?} failed ({:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).expect("stdout is one JSON document")
    }

    fn project_root(&self) -> PathBuf {
        self.data_home.join("projects").join(&self.project_id)
    }

    fn state_file(&self) -> PathBuf {
        self.project_root().join(".daemon/daemon.json")
    }

    fn track(&self, pid: u64) -> u32 {
        let pid = u32::try_from(pid).expect("pid fits u32");
        self.daemons.lock().expect("tracked pids").push(pid);
        pid
    }

    fn recordings(&self) -> Vec<Value> {
        self.ok_json(&["recording", "list"])["recordings"].as_array().expect("recordings").clone()
    }

    /// Persists a begun recording with one durable segment and no finish, exactly the rows a daemon
    /// killed mid-capture leaves behind (writes through the product's own persistence port).
    fn seed_open_recording(&self) -> RecordingId {
        let database = self.project_root().join("metadata.sqlite3");
        let store = SqliteStore::open(&database, OpenOptions::default().with_must_exist(true))
            .expect("open store");
        let persistence = SqliteRecordingPersistence::new(store, self.project_root());
        let project_id: ProjectId = self.project_id.parse().expect("project id");
        let recording_id = RecordingId::new();
        persistence
            .begin_recording(&BeginRecording {
                project_id,
                recording_id,
                runtime_session_id: RuntimeSessionId::new(),
                opened_at: WallTime::now(),
                endpoint_observation:
                    xtrace_application::recording::EndpointObservationInput::default(),
            })
            .expect("begin");
        let payload = XtfEventEnvelope {
            recording_seq: 2,
            event: Some(RecordingEvent {
                event_id: "lifecycle-open-event".to_string(),
                recording_seq: 2,
                monotonic_ns: 5,
                ..RecordingEvent::default()
            }),
        };
        persistence
            .persist_segment(&PersistRecordingSegment {
                project_id,
                recording_id,
                segment_ordinal: 0,
                events: vec![AcceptedRecordingEvent {
                    recording_seq: 2,
                    monotonic_ns: 5,
                    priority: 0,
                    canonical_bytes: payload.encode_to_vec(),
                    payload,
                }],
            })
            .expect("persist segment");
        recording_id
    }
}

fn pid_alive(pid: u32) -> bool {
    Command::new("ps")
        .args(["-p", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn wait_gone(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while pid_alive(pid) {
        assert!(Instant::now() < deadline, "process {pid} did not exit");
        thread::sleep(Duration::from_millis(20));
    }
}

fn run_node_client(bootstrap: &Path) -> Value {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let client = repo_root.join("adapters/node/examples/synthetic-client/dist/main.js");
    assert!(client.is_file(), "build the Node synthetic client first (npm run build)");
    let mut child = Command::new("node")
        .arg(&client)
        .arg(bootstrap)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn node synthetic client");
    let mut stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("synthetic client exceeded 30 seconds");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let (mut out, mut err) = (String::new(), String::new());
    stdout.read_to_string(&mut out).expect("read stdout");
    stderr.read_to_string(&mut err).expect("read stderr");
    assert!(status.success(), "client failed: {err}");
    serde_json::from_str(&out).expect("client receipt JSON")
}

#[test]
fn record_stop_restart_persists_and_reopens_a_recorded_session() {
    let fx = fixture();
    let started = fx.ok_json(&["record"]);
    assert_eq!(started["kind"], "record_started");
    assert_eq!(started["arming"], "single_launch_bootstrap");
    assert_eq!(started["bootstrap_armed"], true);
    let pid = fx.track(started["pid"].as_u64().expect("pid"));
    assert!(pid_alive(pid));
    let session = started["runtime_session_id"].as_str().expect("session").to_string();
    // The state file is private and never holds the bootstrap secret.
    let mode = std::fs::metadata(fx.state_file()).expect("state file").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let state_text = std::fs::read_to_string(fx.state_file()).expect("state");
    let bootstrap_path = PathBuf::from(started["bootstrap_path"].as_str().expect("bootstrap"));
    let secret =
        serde_json::from_slice::<Value>(&std::fs::read(&bootstrap_path).expect("bootstrap"))
            .expect("bootstrap JSON")["session_secret_base64"]
            .as_str()
            .expect("secret")
            .to_string();
    assert!(!state_text.contains(&secret));
    assert!(!String::from_utf8_lossy(&serde_json::to_vec(&started).unwrap()).contains(&secret));

    // record twice returns the same daemon.
    let again = fx.ok_json(&["record"]);
    assert_eq!(again["kind"], "record_already_running");
    assert_eq!(again["pid"], started["pid"]);

    // A real client (the Node synthetic XTP client) records through the running daemon.
    let receipt = run_node_client(&bootstrap_path);
    assert_eq!(receipt["kind"], "synthetic_recording_staged");
    let recorded = receipt["recording_id"].as_str().expect("recording id").to_string();

    // Graceful stop by session id.
    let wrong = fx.xtrace(&["stop", "--session", "00000000-0000-7000-8000-000000000000"]);
    assert_eq!(wrong.status.code(), Some(3), "unknown session is NotFound");
    assert!(pid_alive(pid), "a wrong session id must not stop the daemon");
    let stopped = fx.ok_json(&["stop", "--session", &session]);
    assert_eq!(stopped["kind"], "stopped");
    assert_eq!(stopped["pid"], started["pid"]);
    wait_gone(pid);
    assert!(!fx.state_file().exists(), "state file removed on stop");

    // Stopping again is a clear non-zero.
    let none = fx.xtrace(&["stop"]);
    assert_eq!(none.status.code(), Some(3));
    let error: Value = serde_json::from_slice(&none.stderr).expect("error JSON");
    assert_eq!(error["code"], "XTR-LIFECYCLE-NOT-RUNNING");

    // The recording persisted across the stop.
    let after_stop = fx.recordings();
    assert!(after_stop.iter().any(|r| r["recording_id"] == recorded.as_str()), "{after_stop:?}");

    // Restart preserves the store and brings up a new daemon.
    let restarted = fx.ok_json(&["restart"]);
    assert_eq!(restarted["kind"], "restarted");
    assert_eq!(restarted["previously_running"], false);
    let new_pid = fx.track(restarted["started"]["pid"].as_u64().expect("pid"));
    assert_ne!(new_pid, pid);
    assert!(pid_alive(new_pid));
    let reopened = fx.recordings();
    let row = reopened
        .iter()
        .find(|r| r["recording_id"] == recorded.as_str())
        .expect("recording reopens after restart");
    assert_eq!(row["status"], "complete");
    assert_eq!(row["completion"], "complete");
    let shown = fx.ok_json(&["recording", "show", &recorded]);
    assert_eq!(shown["recording_id"], recorded.as_str());

    fx.ok_json(&["stop"]);
    wait_gone(new_pid);
}

#[test]
fn concurrent_records_are_serialized_and_leave_one_healthy_daemon() {
    let fx = fixture();
    let (a, b) = std::thread::scope(|scope| {
        let first = scope.spawn(|| fx.xtrace(&["record"]));
        let second = scope.spawn(|| fx.xtrace(&["record"]));
        (first.join().expect("first"), second.join().expect("second"))
    });
    for out in [&a, &b] {
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
    let docs: Vec<Value> =
        [&a, &b].iter().map(|o| serde_json::from_slice(&o.stdout).expect("json")).collect();
    let kinds: Vec<&str> = docs.iter().map(|d| d["kind"].as_str().expect("kind")).collect();
    assert!(kinds.contains(&"record_started"), "{kinds:?}");
    assert!(kinds.contains(&"record_already_running"), "{kinds:?}");
    assert_eq!(docs[0]["pid"], docs[1]["pid"], "both name the one daemon");
    fx.track(docs[0]["pid"].as_u64().expect("pid"));
    let stopped = fx.ok_json(&["stop"]);
    assert_eq!(stopped["kind"], "stopped");
}

#[test]
fn restart_while_the_daemon_is_running_replaces_it_and_keeps_the_store() {
    let fx = fixture();
    let started = fx.ok_json(&["record"]);
    let first_pid = fx.track(started["pid"].as_u64().expect("pid"));
    let first_session = started["runtime_session_id"].as_str().expect("session").to_string();

    let restarted = fx.ok_json(&["restart"]);
    assert_eq!(restarted["previously_running"], true, "{restarted}");
    let new_pid = fx.track(restarted["started"]["pid"].as_u64().expect("pid"));
    assert_ne!(new_pid, first_pid, "a new daemon process replaced the old one");
    assert_ne!(
        restarted["started"]["runtime_session_id"].as_str().expect("session"),
        first_session
    );
    wait_gone(first_pid);
    let state: Value =
        serde_json::from_slice(&std::fs::read(fx.state_file()).expect("state file")).expect("json");
    assert_eq!(state["pid"].as_u64(), Some(u64::from(new_pid)), "state names the new daemon");
    let _ = fx.recordings();

    fx.ok_json(&["stop"]);
    wait_gone(new_pid);
}

#[test]
fn restart_seals_a_recording_left_open_and_reopens_it_as_partial() {
    let fx = fixture();
    let started = fx.ok_json(&["record"]);
    let pid = fx.track(started["pid"].as_u64().expect("pid"));
    // Hard-kill exactly the daemon this test started (PID from the CLI document).
    let status = Command::new("kill").args(["-KILL", &pid.to_string()]).status().expect("kill");
    assert!(status.success());
    wait_gone(pid);
    // A stale state file remains; the next stop refuses to claim a dead daemon is running.
    assert!(fx.state_file().exists());

    let open_id = fx.seed_open_recording();
    let before = fx.recordings();
    let row = before
        .iter()
        .find(|r| r["recording_id"] == open_id.to_string().as_str())
        .expect("seeded recording listed");
    assert_eq!(row["status"], "recording", "precondition: left open by the killed daemon");

    let restarted = fx.ok_json(&["restart"]);
    assert_eq!(restarted["previously_running"], false);
    let recovered = restarted["stopped"]["recovered_recordings"].as_array().expect("recovered");
    assert_eq!(recovered.len(), 1, "{restarted}");
    assert_eq!(recovered[0]["recording_id"], open_id.to_string().as_str());
    assert_eq!(recovered[0]["completion"], "partial");
    fx.track(restarted["started"]["pid"].as_u64().expect("pid"));

    let after = fx.recordings();
    let row = after
        .iter()
        .find(|r| r["recording_id"] == open_id.to_string().as_str())
        .expect("interrupted recording reopens");
    assert_eq!(row["status"], "partial");
    assert_eq!(row["completion"], "partial");
    assert_eq!(row["event_count"], "1");
    let shown = fx.ok_json(&["recording", "show", &open_id.to_string()]);
    assert_eq!(shown["recording_id"], open_id.to_string().as_str());
    fx.ok_json(&["stop"]);
}

#[test]
fn stop_signals_only_identified_daemon_pid() {
    let fx = fixture();
    // An unrelated live process that this test owns.
    let mut bystander = Command::new("/bin/sleep").arg("60").spawn().expect("spawn bystander");
    let bystander_pid = bystander.id();
    // Forge a state file that points at the bystander with a plausible but wrong identity.
    let started = fx.ok_json(&["record"]);
    let real_pid = fx.track(started["pid"].as_u64().expect("pid"));
    let mut state: Value =
        serde_json::from_str(&std::fs::read_to_string(fx.state_file()).unwrap()).unwrap();
    state["pid"] = Value::from(bystander_pid);
    std::fs::write(fx.state_file(), serde_json::to_vec(&state).unwrap()).expect("forge");
    let out = fx.xtrace(&["stop"]);
    assert_eq!(out.status.code(), Some(4), "identity mismatch is a conflict");
    let error: Value = serde_json::from_slice(&out.stderr).expect("error JSON");
    assert_eq!(error["code"], "XTR-LIFECYCLE-IDENTITY-MISMATCH");
    assert!(pid_alive(bystander_pid), "the bystander must never be signalled");
    assert!(pid_alive(real_pid), "the real daemon is untouched by a refused stop");
    // Repair the state and stop for real.
    state["pid"] = Value::from(real_pid);
    std::fs::write(fx.state_file(), serde_json::to_vec(&state).unwrap()).expect("repair");
    fx.ok_json(&["stop"]);
    wait_gone(real_pid);
    assert!(pid_alive(bystander_pid));
    bystander.kill().expect("kill own bystander");
    bystander.wait().expect("reap own bystander");
}

#[test]
fn stop_when_not_running_is_clear_nonzero_and_record_validates_depth() {
    let fx = fixture();
    let out = fx.xtrace(&["stop"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(out.stdout.is_empty());
    let error: Value = serde_json::from_slice(&out.stderr).expect("error JSON");
    assert_eq!(error["code"], "XTR-LIFECYCLE-NOT-RUNNING");
    let bad = fx.xtrace(&["record", "--capture-depth", "deep"]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(!fx.state_file().exists(), "a rejected record starts nothing");
    let _ = &fx.root;
}

#[test]
fn record_refuses_when_a_foreground_daemon_owns_the_lock_and_never_signals_it() {
    let fx = fixture();
    let mut foreground = ChildGuard(Some(
        Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["daemon", "--project-dir"])
            .arg(&fx.repo)
            .env("XTRACE_DATA_HOME", &fx.data_home)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn foreground daemon"),
    ));
    let mut line = String::new();
    {
        use std::io::BufRead as _;
        let mut reader = std::io::BufReader::new(
            foreground.0.as_mut().expect("child").stdout.take().expect("stdout"),
        );
        reader.read_line(&mut line).expect("readiness");
        assert!(line.contains("daemon_bound"));
        let out = fx.xtrace(&["record"]);
        assert_eq!(out.status.code(), Some(5), "{}", String::from_utf8_lossy(&out.stderr));
        let out = fx.xtrace(&["stop"]);
        assert_eq!(out.status.code(), Some(4), "a daemon we did not start is not signalled");
        assert!(
            foreground.0.as_mut().expect("child").try_wait().expect("poll").is_none(),
            "foreground daemon still alive"
        );
        let mut own = foreground.0.take().expect("child");
        own.kill().expect("kill own child");
        own.wait().expect("reap own child");
    }
}
