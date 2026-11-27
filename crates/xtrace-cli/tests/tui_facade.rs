//! CLI-level facade integration tests for `xtrace tui` (`--plain`, `--json`, and interactive PTY)
//! backed by a real private `0700`/`0600` `SqliteStore`.

#![cfg(unix)]
#![allow(missing_docs, reason = "integration test symbols are executable fixtures")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests assert on real CLI subprocess output and private fixture state"
)]

use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};

use prost::Message as _;
use serde_json::Value;
use tempfile::TempDir;
use xtrace_application::recording::{
    AcceptedRecordingEvent, BeginRecording, EndpointObservationInput, FinishRecording,
    LIMITATION_CAPTURE_POLICY_NOT_ARMED, PersistRecordingSegment, RecordingPersistencePort as _,
    STANDARD_EVENT_CAP,
};
use xtrace_domain::{
    OutcomeException, OutcomeKind, ProjectId, RecordingId, RecordingOutcome, RuntimeSessionId,
    WallTime,
};
use xtrace_protocol::generated::agent::{
    BindingRole, CapturedValue as WireValue, CapturedValueCaptured, CapturedValueDropped,
    CapturedValueRedacted, CapturedValueTruncated, CapturedValueUnavailable, GapPayload, GapReason,
    NameOrigin, RecordingEvent, RecordingEventKind, SourceBinding, SourceRange, ValueBinding,
    ValueShape, captured_value::Value as WireVariant,
};
use xtrace_protocol::xtf::XtfEventEnvelope;
use xtrace_store::{OpenOptions, SqliteRecordingPersistence, SqliteStore};

struct Fixture {
    _root: TempDir,
    repo: PathBuf,
    data_home: PathBuf,
    project_id: ProjectId,
}

impl Fixture {
    fn init() -> Self {
        let base = std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .canonicalize()
            .expect("canonical temp base");
        let root = tempfile::Builder::new()
            .prefix("xt-tui-facade-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(base)
            .expect("create private temp root");
        let repo = root.path().join("repo");
        let data_home = root.path().join("data");
        std::fs::create_dir_all(&repo).expect("create repo dir");

        let init = Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .args(["init", "--project-dir"])
            .arg(&repo)
            .env("XTRACE_DATA_HOME", &data_home)
            .stdin(Stdio::null())
            .output()
            .expect("run xtrace init");
        assert!(
            init.status.success(),
            "xtrace init failed: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let doc: Value = serde_json::from_slice(&init.stdout).expect("init JSON");
        let project_id: ProjectId =
            doc["project_id"].as_str().expect("project_id").parse().expect("parse project_id");
        let project_root = data_home.join("projects").join(project_id.to_string());
        let dir_mode =
            std::fs::metadata(&project_root).expect("project dir metadata").permissions().mode()
                & 0o777;
        let db_mode = std::fs::metadata(project_root.join("metadata.sqlite3"))
            .expect("db metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "project directory must be owner-only");
        assert_eq!(db_mode, 0o600, "sqlite store must be owner-only");

        Self { _root: root, repo, data_home, project_id }
    }

    fn project_root(&self) -> PathBuf {
        self.data_home.join("projects").join(self.project_id.to_string())
    }

    fn persistence(&self) -> SqliteRecordingPersistence {
        let store = SqliteStore::open(
            &self.project_root().join("metadata.sqlite3"),
            OpenOptions::default().with_must_exist(true),
        )
        .expect("open private metadata.sqlite3");
        SqliteRecordingPersistence::new(store, self.project_root())
    }

    fn tui(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_xtrace"))
            .arg("tui")
            .args(args)
            .arg("--project-dir")
            .arg(&self.repo)
            .env("XTRACE_DATA_HOME", &self.data_home)
            .stdin(Stdio::null())
            .output()
            .expect("run xtrace tui")
    }
}

fn event(
    seq: u64,
    event_id: &str,
    parent_id: &str,
    kind: RecordingEventKind,
    symbol: &str,
) -> AcceptedRecordingEvent<XtfEventEnvelope> {
    let payload = XtfEventEnvelope {
        recording_seq: seq,
        event: Some(RecordingEvent {
            event_id: event_id.to_owned(),
            parent_event_id: parent_id.to_owned(),
            recording_seq: seq,
            monotonic_ns: seq * 10,
            kind: kind as i32,
            symbol: symbol.to_owned(),
            ..RecordingEvent::default()
        }),
    };
    AcceptedRecordingEvent {
        recording_seq: seq,
        monotonic_ns: seq * 10,
        priority: 0,
        canonical_bytes: payload.encode_to_vec(),
        payload,
    }
}

fn finish(
    persistence: &SqliteRecordingPersistence,
    recording_id: RecordingId,
    events: &[AcceptedRecordingEvent<XtfEventEnvelope>],
    outcome: Option<RecordingOutcome>,
) {
    let mut digest = blake3::Hasher::new();
    for item in events {
        let id = &item.payload.event.as_ref().expect("event").event_id;
        digest.update(id.as_bytes());
    }
    let last_seq = events.last().map_or(1, |e| e.recording_seq);
    persistence
        .finish_recording(&FinishRecording {
            recording_id,
            final_recording_seq: last_seq,
            duration_ns: Some(250),
            event_digest: digest.finalize().as_bytes().to_vec(),
            drop_counts_by_priority: BTreeMap::new(),
            unsupported_capability_codes: Vec::new(),
            capacity_dropped_events: 0,
            event_cap: STANDARD_EVENT_CAP as u64,
            response_summary: None,
            outcome,
        })
        .expect("finish recording");
}

#[test]
fn tui_plain_and_json_render_routes_outcomes_gaps_bindings_source_and_truncations_without_canary() {
    let fx = Fixture::init();
    let persistence = fx.persistence();
    let session = RuntimeSessionId::new();

    // Place a private source canary on disk with a mismatched content hash so the source projection
    // never reveals it.
    let src_dir = fx.repo.join("src/main/java");
    std::fs::create_dir_all(&src_dir).expect("src dir");
    std::fs::write(
        src_dir.join("Owners.java"),
        "class Owners { String k = \"PRIVATE_SOURCE_CANARY_777\"; }\n",
    )
    .expect("write source");

    let symbol_canary = "PRIVATE_SYMBOL_CANARY_999";
    let rec_rich = RecordingId::new();
    persistence
        .begin_recording(&BeginRecording {
            project_id: fx.project_id,
            recording_id: rec_rich,
            runtime_session_id: session,
            opened_at: WallTime::from_parts(2026, 9, 29, 2, 0, 2, 0).expect("time"),
            endpoint_observation: EndpointObservationInput::default(),
            limitations: vec![LIMITATION_CAPTURE_POLICY_NOT_ARMED.to_owned()],
        })
        .expect("begin rec_rich");

    let e_req = event(
        2,
        "rich-req",
        "",
        RecordingEventKind::RequestUpdate,
        "http.request GET /owners/{ownerId}",
    );
    let mut e_enter = event(
        3,
        "rich-enter",
        "",
        RecordingEventKind::FrameEnter,
        "dev.xtrace.OwnerController.show",
    );
    e_enter.payload.event.as_mut().expect("event").bindings = vec![
        ValueBinding {
            name: "ownerId".to_owned(),
            role: BindingRole::Argument as i32,
            name_origin: NameOrigin::Declared as i32,
            value: Some(WireValue {
                value: Some(WireVariant::Captured(CapturedValueCaptured {
                    shape: ValueShape::Integer64 as i32,
                    preview: "42".to_owned(),
                    content_hash: blake3::hash(b"42").as_bytes().to_vec().into(),
                })),
            }),
        },
        ValueBinding {
            name: "authHeader".to_owned(),
            role: BindingRole::Argument as i32,
            name_origin: NameOrigin::Declared as i32,
            value: Some(WireValue {
                value: Some(WireVariant::Redacted(CapturedValueRedacted {
                    rule_id: "secret-header".to_owned(),
                    shape_hint: ValueShape::String as i32,
                })),
            }),
        },
        ValueBinding {
            name: "requestBody".to_owned(),
            role: BindingRole::Argument as i32,
            name_origin: NameOrigin::Declared as i32,
            value: Some(WireValue {
                value: Some(WireVariant::Truncated(CapturedValueTruncated {
                    preview: "body-head".to_owned(),
                    original_size_lower_bound: 4096,
                    limit: 64,
                })),
            }),
        },
        ValueBinding {
            name: "localVar".to_owned(),
            role: BindingRole::Local as i32,
            name_origin: NameOrigin::Declared as i32,
            value: Some(WireValue {
                value: Some(WireVariant::Unavailable(CapturedValueUnavailable { reason: 6 })),
            }),
        },
        ValueBinding {
            name: "bigList".to_owned(),
            role: BindingRole::Local as i32,
            name_origin: NameOrigin::Declared as i32,
            value: Some(WireValue {
                value: Some(WireVariant::Dropped(CapturedValueDropped { reason: 7 })),
            }),
        },
    ];
    e_enter.canonical_bytes = e_enter.payload.encode_to_vec();

    let mut e_line = event(4, "rich-line", "rich-enter", RecordingEventKind::LineCursor, "");
    {
        let nested = e_line.payload.event.as_mut().expect("event");
        nested.source_binding = SourceBinding::ObservedUnattested as i32;
        nested.source = Some(SourceRange {
            path: "src/main/java/Owners.java".to_owned(),
            start_line: 1,
            end_line: 1,
            content_hash: vec![9; 32].into(),
            ..SourceRange::default()
        });
    }
    e_line.canonical_bytes = e_line.payload.encode_to_vec();

    let oversized_symbol = format!("{}_{symbol_canary}", "s".repeat(270));
    let e_trunc =
        event(5, "rich-trunc", "rich-enter", RecordingEventKind::FrameEnter, &oversized_symbol);
    let mut e_gap = event(6, "rich-gap", "rich-enter", RecordingEventKind::Gap, "");
    e_gap.payload.event.as_mut().expect("event").gap = Some(GapPayload {
        reason: GapReason::LineBudget as i32,
        count: 9,
        first_recording_seq: 5,
        last_recording_seq: 5,
    });
    e_gap.canonical_bytes = e_gap.payload.encode_to_vec();

    let rich_events = vec![e_req, e_enter, e_line, e_trunc, e_gap];
    persistence
        .persist_segment(&PersistRecordingSegment {
            project_id: fx.project_id,
            recording_id: rec_rich,
            segment_ordinal: 0,
            events: rich_events.clone(),
        })
        .expect("persist rich segment");
    finish(
        &persistence,
        rec_rich,
        &rich_events,
        Some(RecordingOutcome {
            kind: OutcomeKind::Responded,
            http_status: Some(200),
            exception: None,
            thrown_from_event_id: None,
        }),
    );

    // Second recording linked via EndpointObservationInput (POST /orders) with an exception outcome.
    let rec_orders = RecordingId::new();
    persistence
        .begin_recording(&BeginRecording {
            project_id: fx.project_id,
            recording_id: rec_orders,
            runtime_session_id: session,
            opened_at: WallTime::from_parts(2026, 9, 29, 2, 0, 1, 0).expect("time"),
            endpoint_observation: EndpointObservationInput {
                policy_id: Some("spring-orders-v1".to_owned()),
                application_component: Some("spring-fixture".to_owned()),
                binding_key: Some("default".to_owned()),
                method: "POST".to_owned(),
                route_template: "/orders".to_owned(),
            },
            limitations: Vec::new(),
        })
        .expect("begin rec_orders");
    let order_events =
        vec![event(2, "ord-enter", "", RecordingEventKind::FrameEnter, "OrderCtrl.create")];
    persistence
        .persist_segment(&PersistRecordingSegment {
            project_id: fx.project_id,
            recording_id: rec_orders,
            segment_ordinal: 0,
            events: order_events.clone(),
        })
        .expect("persist orders segment");
    finish(
        &persistence,
        rec_orders,
        &order_events,
        Some(RecordingOutcome {
            kind: OutcomeKind::ExceptionPropagated,
            http_status: Some(500),
            exception: Some(OutcomeException {
                exception_type: "IllegalStateException".to_owned(),
                message: "boom".to_owned(),
            }),
            thrown_from_event_id: Some("ord-enter".to_owned()),
        }),
    );

    // 1) List view: --plain and --json
    let list_plain = fx.tui(&["--plain"]);
    assert!(list_plain.status.success(), "{}", String::from_utf8_lossy(&list_plain.stderr));
    let list_text = String::from_utf8_lossy(&list_plain.stdout);
    assert!(!list_text.contains('\u{1b}'), "plain output must not contain ANSI escapes");
    assert!(
        list_text.contains(&format!(
            "> {rec_rich}  partial  5 events  GET /owners/{{ownerId}}  responded"
        )),
        "{list_text}"
    );
    assert!(
        list_text.contains(&format!(
            "  {rec_orders}  complete  1 events  POST /orders  exception_propagated"
        )),
        "{list_text}"
    );
    assert!(!list_text.contains(symbol_canary));
    assert!(!list_text.contains("PRIVATE_SOURCE_CANARY_777"));

    let list_json = fx.tui(&["--json"]);
    assert!(list_json.status.success(), "{}", String::from_utf8_lossy(&list_json.stderr));
    let list_doc: Value = serde_json::from_slice(&list_json.stdout).expect("list JSON");
    let list_rows = list_doc["rows"].as_array().expect("rows array");
    assert!(
        list_rows.iter().any(|r| r.as_str().is_some_and(|s| s.contains("GET /owners/{ownerId}")))
    );

    // 2) Detail view: --recording <id> --plain and --json
    let rec_arg = rec_rich.to_string();
    let detail_plain = fx.tui(&["--recording", &rec_arg, "--plain"]);
    assert!(detail_plain.status.success(), "{}", String::from_utf8_lossy(&detail_plain.stderr));
    let detail_text = String::from_utf8_lossy(&detail_plain.stdout);
    assert!(!detail_text.contains('\u{1b}'));
    assert!(detail_text.contains("route: GET /owners/{ownerId}"), "{detail_text}");
    assert!(detail_text.contains("outcome: responded 200"), "{detail_text}");
    assert!(detail_text.contains("limitations: capture_policy_not_armed"), "{detail_text}");
    assert!(detail_text.contains("GAP: line_budget (9 suppressed)"), "{detail_text}");
    assert!(detail_text.contains("src/main/java/Owners.java:1"), "{detail_text}");
    assert!(detail_text.contains("ownerId (integer): 42"), "{detail_text}");
    assert!(detail_text.contains("[redacted by secret-header; string]"), "{detail_text}");
    assert!(detail_text.contains("[truncated 64/4096B] body-head"), "{detail_text}");
    assert!(detail_text.contains("[unavailable: focused_capture_not_armed]"), "{detail_text}");
    assert!(detail_text.contains("[dropped: value_budget]"), "{detail_text}");
    assert!(detail_text.contains("truncated fields: symbol (truncated,"), "{detail_text}");
    assert!(!detail_text.contains(symbol_canary), "symbol canary leaked: {detail_text}");
    assert!(
        !detail_text.contains("PRIVATE_SOURCE_CANARY_777"),
        "source canary leaked: {detail_text}"
    );

    let detail_json = fx.tui(&["--recording", &rec_arg, "--json"]);
    assert!(detail_json.status.success(), "{}", String::from_utf8_lossy(&detail_json.stderr));
    let detail_doc: Value = serde_json::from_slice(&detail_json.stdout).expect("detail JSON");
    let detail_rows = detail_doc["rows"].as_array().expect("rows");
    assert!(
        detail_rows
            .iter()
            .any(|r| r.as_str().is_some_and(|s| s.contains("GAP: line_budget (9 suppressed)")))
    );

    let orders_arg = rec_orders.to_string();
    let orders_plain = fx.tui(&["--recording", &orders_arg, "--plain"]);
    assert!(orders_plain.status.success());
    let orders_text = String::from_utf8_lossy(&orders_plain.stdout);
    assert!(orders_text.contains("route: POST /orders"), "{orders_text}");
    assert!(
        orders_text.contains("outcome: exception_propagated 500 (IllegalStateException)"),
        "{orders_text}"
    );
}

struct PtyDriver {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    finished: bool,
}

impl Drop for PtyDriver {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl PtyDriver {
    fn spawn(xtrace: &Path, repo: &Path, data_home: &Path, cols: u16, rows: u16) -> Self {
        let script = r#"
import fcntl, json, os, pty, select, struct, sys, termios, time

cols, rows = int(sys.argv[1]), int(sys.argv[2])
argv = sys.argv[3:]
pid, fd = pty.fork()
if pid == 0:
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    os.execv(argv[0], argv)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
out = bytearray()
pos = 0
eof = False

def pump(seconds):
    global eof
    if eof:
        return False
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        r, _, _ = select.select([fd], [], [], min(0.05, max(0.0, end - time.monotonic())))
        if r:
            try:
                data = os.read(fd, 65536)
            except OSError:
                eof = True
                return False
            if not data:
                eof = True
                return False
            out.extend(data)
    return True

for line in sys.stdin:
    cmd = json.loads(line)
    op = cmd["op"]
    if op == "send":
        os.write(fd, cmd["text"].encode())
        pump(0.1)
        sys.stdout.write(json.dumps({"ok": True}) + "\n")
        sys.stdout.flush()
    elif op == "wait":
        needle = cmd["needle"].encode()
        deadline = time.monotonic() + cmd["timeout"]
        while time.monotonic() < deadline and needle not in out[pos:]:
            if not pump(0.05):
                break
        found = out.find(needle, pos)
        if found >= 0:
            pos = found + len(needle)
            sys.stdout.write(json.dumps({"ok": True}) + "\n")
        else:
            sys.stdout.write(json.dumps({"ok": False, "tail": out[max(0, pos - 200):].decode("utf-8", "replace")}) + "\n")
        sys.stdout.flush()
    elif op == "finish":
        deadline = time.monotonic() + 3.0
        status = None
        while time.monotonic() < deadline:
            pump(0.05)
            done, st = os.waitpid(pid, os.WNOHANG)
            if done:
                status = st
                break
        if status is None:
            os.kill(pid, 9)
            _, status = os.waitpid(pid, 0)
        while not eof:
            r, _, _ = select.select([fd], [], [], 0)
            if not r:
                break
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            out.extend(data)
        os.close(fd)
        code = os.waitstatus_to_exitcode(status)
        sys.stdout.write(json.dumps({"exit": code, "output": out.decode("utf-8", "replace")}) + "\n")
        sys.stdout.flush()
        break
"#;
        let mut child = Command::new("python3")
            .arg("-I")
            .arg("-c")
            .arg(script)
            .arg(cols.to_string())
            .arg(rows.to_string())
            .arg(xtrace)
            .args(["tui", "--project-dir"])
            .arg(repo)
            .env("XTRACE_DATA_HOME", data_home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn python3 PTY driver");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        Self { child, stdin, stdout, finished: false }
    }

    fn cmd(&mut self, payload: &Value) -> Value {
        let mut line = serde_json::to_string(payload).expect("serialize cmd");
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).expect("write cmd");
        self.stdin.flush().expect("flush cmd");
        let mut reply = String::new();
        self.stdout.read_line(&mut reply).expect("read reply");
        serde_json::from_str(&reply).expect("parse reply")
    }

    fn wait(&mut self, needle: &str) {
        let res = self.cmd(&serde_json::json!({ "op": "wait", "needle": needle, "timeout": 8.0 }));
        assert_eq!(res["ok"].as_bool(), Some(true), "did not observe {needle:?}: {res}");
    }

    fn send(&mut self, text: &str) {
        let res = self.cmd(&serde_json::json!({ "op": "send", "text": text }));
        assert_eq!(res["ok"].as_bool(), Some(true), "send failed: {res}");
    }

    fn finish(mut self) -> (i64, String) {
        let res = self.cmd(&serde_json::json!({ "op": "finish" }));
        self.finished = true;
        let status = self.child.wait().expect("wait python3");
        assert!(status.success(), "python3 PTY driver failed");
        (res["exit"].as_i64().expect("exit"), res["output"].as_str().expect("output").to_owned())
    }
}

#[test]
fn tui_discloses_paging_truncation_pages_list_and_window_and_reconnects_live() {
    let fx = Fixture::init();
    let persistence = fx.persistence();
    let session = RuntimeSessionId::new();

    // Seed 54 small older recordings + 1 newest 505-event recording = 55 recordings (> 50 list limit).
    let mut oldest_id = None;
    for index in 0..54_u8 {
        let id = RecordingId::new();
        if index == 0 {
            oldest_id = Some(id);
        }
        persistence
            .begin_recording(&BeginRecording {
                project_id: fx.project_id,
                recording_id: id,
                runtime_session_id: session,
                opened_at: WallTime::from_parts(2026, 9, 29, 1, 0, index, 0).expect("time"),
                endpoint_observation: EndpointObservationInput::default(),
                limitations: Vec::new(),
            })
            .expect("begin older");
        let events = vec![event(
            2,
            &format!("old-{index}-req"),
            "",
            RecordingEventKind::RequestUpdate,
            "http.request GET /owners",
        )];
        persistence
            .persist_segment(&PersistRecordingSegment {
                project_id: fx.project_id,
                recording_id: id,
                segment_ordinal: 0,
                events: events.clone(),
            })
            .expect("seg older");
        finish(&persistence, id, &events, None);
    }
    let oldest_id = oldest_id.expect("oldest recording");

    let big_id = RecordingId::new();
    persistence
        .begin_recording(&BeginRecording {
            project_id: fx.project_id,
            recording_id: big_id,
            runtime_session_id: session,
            opened_at: WallTime::from_parts(2026, 9, 29, 2, 0, 0, 0).expect("time"),
            endpoint_observation: EndpointObservationInput {
                policy_id: Some("spring-orders-v1".to_owned()),
                application_component: Some("spring-fixture".to_owned()),
                binding_key: Some("default".to_owned()),
                method: "POST".to_owned(),
                route_template: "/orders".to_owned(),
            },
            limitations: Vec::new(),
        })
        .expect("begin big");
    let seg0: Vec<_> = (0..500_u64)
        .map(|i| {
            let seq = i + 2;
            event(
                seq,
                &format!("big-{seq}"),
                "",
                RecordingEventKind::FrameEnter,
                &format!("Scale.f{seq}"),
            )
        })
        .collect();
    let seg1: Vec<_> = (500..505_u64)
        .map(|i| {
            let seq = i + 2;
            event(
                seq,
                &format!("big-{seq}"),
                "",
                RecordingEventKind::FrameEnter,
                &format!("Scale.f{seq}"),
            )
        })
        .collect();
    persistence
        .persist_segment(&PersistRecordingSegment {
            project_id: fx.project_id,
            recording_id: big_id,
            segment_ordinal: 0,
            events: seg0.clone(),
        })
        .expect("big seg0");
    persistence
        .persist_segment(&PersistRecordingSegment {
            project_id: fx.project_id,
            recording_id: big_id,
            segment_ordinal: 1,
            events: seg1.clone(),
        })
        .expect("big seg1");
    let mut big_all = seg0;
    big_all.extend(seg1);
    finish(
        &persistence,
        big_id,
        &big_all,
        Some(RecordingOutcome {
            kind: OutcomeKind::Responded,
            http_status: Some(201),
            exception: None,
            thrown_from_event_id: None,
        }),
    );

    // --plain checks truncation disclosure on list and window.
    let list_plain = fx.tui(&["--plain"]);
    assert!(list_plain.status.success());
    let list_text = String::from_utf8_lossy(&list_plain.stdout);
    assert!(list_text.contains("truncated: more recordings exist"), "{list_text}");

    let big_arg = big_id.to_string();
    let win_plain = fx.tui(&["--recording", &big_arg, "--plain"]);
    assert!(win_plain.status.success());
    let win_text = String::from_utf8_lossy(&win_plain.stdout);
    let shown: u64 = win_text
        .split("more events exist beyond the ")
        .nth(1)
        .and_then(|rest| rest.split(" shown").next())
        .and_then(|num| num.parse().ok())
        .unwrap_or_else(|| panic!("expected bounded window truncation disclosure: {win_text}"));
    assert!(shown > 0 && shown < 505, "expected bounded page < 505, got {shown}: {win_text}");
    assert!(win_text.contains("page: n next"), "{win_text}");
    let page2_first_symbol = format!("Scale.f{}", shown + 2);

    // Interactive PTY checks list paging, window cursor paging, and live reconnect after store write.
    let mut pty =
        PtyDriver::spawn(Path::new(env!("CARGO_BIN_EXE_xtrace")), &fx.repo, &fx.data_home, 120, 40);
    pty.wait("truncated: more recordings exist");
    pty.send("n");
    pty.wait(&oldest_id.to_string());
    pty.send("p");
    pty.wait(&big_arg);
    pty.send("\r");
    pty.wait("route: POST /orders");
    pty.wait("page: n next");
    pty.send("n");
    pty.wait(&page2_first_symbol);
    pty.wait("page: p prev");
    pty.send("p");
    pty.wait("Scale.f2");
    pty.send("b");
    pty.wait("truncated: more recordings exist");

    // Persist a brand-new recording into the store while `xtrace tui` is live, then press `R` to reconnect.
    let rec_new = RecordingId::new();
    persistence
        .begin_recording(&BeginRecording {
            project_id: fx.project_id,
            recording_id: rec_new,
            runtime_session_id: session,
            opened_at: WallTime::from_parts(2026, 9, 29, 3, 0, 0, 0).expect("time"),
            endpoint_observation: EndpointObservationInput::default(),
            limitations: Vec::new(),
        })
        .expect("begin new");
    let new_events =
        vec![event(2, "new-req", "", RecordingEventKind::RequestUpdate, "http.request GET /vets")];
    persistence
        .persist_segment(&PersistRecordingSegment {
            project_id: fx.project_id,
            recording_id: rec_new,
            segment_ordinal: 0,
            events: new_events.clone(),
        })
        .expect("seg new");
    finish(&persistence, rec_new, &new_events, None);

    pty.send("R");
    pty.wait("GET /vets");
    pty.send("q");
    let (exit, output) = pty.finish();
    assert_eq!(exit, 0, "unexpected exit {exit}: {output}");
    assert!(output.ends_with("\u{1b}[?25h\u{1b}[?1049l"), "terminal not restored");
}
