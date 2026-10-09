//! Golden protocol fixtures and wire-contract guards (CONTRACTS section 1.4).
//!
//! `schema/fixtures/xtp-agent/*.json` hold hex-encoded `AgentEnvelope` bytes plus a human summary of
//! the fields they carry. Java hand-codes its framing against these files and Node decodes them
//! with the generated types. Create an empty `schema/fixtures/xtp-agent/.regen` marker file to rewrite the files from the Rust
//! definitions below (the leased runner scrubs environment variables); the default run only verifies.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use prost::Message as _;
use prost::bytes::Bytes;
use serde_json::{Value, json};
use xtrace_protocol::generated::agent as wire;
use xtrace_protocol::generated::agent::agent_envelope::Payload;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schema/fixtures/xtp-agent")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn envelope(seq: u64, payload: Payload) -> wire::AgentEnvelope {
    wire::AgentEnvelope {
        protocol_major: 1,
        protocol_minor: 0,
        runtime_session_id: Bytes::from(vec![0x11; 16]),
        session_seq: seq,
        sent_monotonic_ns: 1_000 + seq,
        message_id: format!("m-{seq}"),
        correlation_token: String::new(),
        payload: Some(payload),
    }
}

fn captured(preview: &str) -> wire::CapturedValue {
    wire::CapturedValue {
        value: Some(wire::captured_value::Value::Captured(wire::CapturedValueCaptured {
            shape: wire::ValueShape::String as i32,
            preview: preview.to_string(),
            content_hash: Bytes::from(vec![0xAB; 32]),
        })),
    }
}

fn source(path: &str, line: u32) -> wire::SourceRange {
    wire::SourceRange {
        path: path.to_string(),
        start_line: line,
        start_column: 0,
        end_line: line,
        end_column: 0,
        content_hash: Bytes::from(vec![0xCD; 32]),
    }
}

fn event(seq: u64, kind: wire::RecordingEventKind) -> wire::RecordingEvent {
    wire::RecordingEvent {
        event_id: format!("e-{seq}"),
        recording_seq: seq,
        parent_event_id: String::new(),
        async_parent_event_id: String::new(),
        monotonic_ns: 5_000 + seq,
        priority: 30,
        kind: kind as i32,
        symbol: String::new(),
        source: None,
        value: None,
        interaction: None,
        exception: None,
        source_binding: 0,
        bindings: Vec::new(),
        gap: None,
    }
}

fn batch(events: Vec<wire::RecordingEvent>) -> Payload {
    Payload::EventBatch(wire::EventBatch { recording_id: Bytes::from(vec![0x22; 16]), events })
}

fn started(policy: &str, exercise_item: &str) -> wire::RecordingStarted {
    wire::RecordingStarted {
        recording_id: Bytes::from(vec![0x22; 16]),
        recording_seq: 1,
        method: "GET".to_string(),
        matched_route_template: "/owners/{id}".to_string(),
        url_shape: "/owners/{id}".to_string(),
        operation_candidates: Vec::new(),
        start_monotonic_ns: 4_000,
        thread_or_task_id: "t-1".to_string(),
        async_context_id: String::new(),
        capture_policy_id: policy.to_string(),
        capture_policy_digest: String::new(),
        redaction_policy_digest: String::new(),
        source_revision_id: String::new(),
        exercise_item_id: exercise_item.to_string(),
    }
}

fn finished(outcome: Option<wire::RecordingOutcome>) -> wire::RecordingFinished {
    wire::RecordingFinished {
        recording_id: Bytes::from(vec![0x22; 16]),
        final_recording_seq: 9,
        duration_ns: 12_000,
        response_summary: None,
        drop_counts_by_priority: std::collections::HashMap::new(),
        unsupported_capability_codes: Vec::new(),
        event_digest: Bytes::from(vec![0xEE; 32]),
        outcome,
    }
}

fn binding(
    name: &str,
    role: wire::BindingRole,
    origin: wire::NameOrigin,
    value: wire::CapturedValue,
) -> wire::ValueBinding {
    wire::ValueBinding {
        name: name.to_string(),
        role: role as i32,
        name_origin: origin as i32,
        value: Some(value),
    }
}

type FixtureCase = (&'static str, &'static str, wire::AgentEnvelope, Value);

fn cases() -> Vec<FixtureCase> {
    use wire::captured_value::Value as V;
    let mut all_states = event(2, wire::RecordingEventKind::FrameEnter);
    all_states.symbol = "OwnerController.show".to_string();
    all_states.source = Some(source("src/main/java/app/OwnerController.java", 40));
    all_states.source_binding = wire::SourceBinding::ObservedUnattested as i32;
    all_states.bindings = vec![
        binding("id", wire::BindingRole::Argument, wire::NameOrigin::Declared, captured("42")),
        binding(
            "password",
            wire::BindingRole::Argument,
            wire::NameOrigin::Declared,
            wire::CapturedValue {
                value: Some(V::Redacted(wire::CapturedValueRedacted {
                    rule_id: "name.secret".to_string(),
                    shape_hint: wire::ValueShape::String as i32,
                })),
            },
        ),
        binding(
            "arg2",
            wire::BindingRole::Argument,
            wire::NameOrigin::Synthesized,
            wire::CapturedValue {
                value: Some(V::Truncated(wire::CapturedValueTruncated {
                    preview: "aaaa".to_string(),
                    original_size_lower_bound: 4096,
                    limit: 256,
                })),
            },
        ),
        binding(
            "this",
            wire::BindingRole::Receiver,
            wire::NameOrigin::Declared,
            wire::CapturedValue {
                value: Some(V::Unavailable(wire::CapturedValueUnavailable {
                    reason: wire::UnavailableReason::FocusedCaptureNotArmed as i32,
                })),
            },
        ),
        binding(
            "extra",
            wire::BindingRole::Argument,
            wire::NameOrigin::Declared,
            wire::CapturedValue {
                value: Some(V::Dropped(wire::CapturedValueDropped {
                    reason: wire::DropReason::ValueBudget as i32,
                })),
            },
        ),
    ];

    let mut line = event(3, wire::RecordingEventKind::LineCursor);
    line.symbol = "OwnerController.show".to_string();
    line.source = Some(source("src/main/java/app/OwnerController.java", 41));
    line.source_binding = wire::SourceBinding::ObservedUnattested as i32;
    line.priority = 20;

    let mut gap = event(4, wire::RecordingEventKind::Gap);
    gap.priority = 20;
    gap.gap = Some(wire::GapPayload {
        reason: wire::GapReason::LineBudget as i32,
        count: 7,
        first_recording_seq: 5,
        last_recording_seq: 11,
    });

    let mut interaction = event(5, wire::RecordingEventKind::DatabaseStart);
    interaction.interaction = Some(wire::Interaction {
        kind: wire::InteractionKind::Database as i32,
        driver: "jdbc".to_string(),
        schema: "public".to_string(),
        table: "owners".to_string(),
        host: "db.local".to_string(),
        method: "executeQuery".to_string(),
        path: String::new(),
        request_summary: None,
        response_summary: None,
        error: None,
        statement_kind: "select".to_string(),
        tables: vec!["owners".to_string(), "pets".to_string()],
        sanitized_shape: "select * from owners where id = ?".to_string(),
        port: 5432,
        status_code: 0,
    });
    let mut process = event(6, wire::RecordingEventKind::OutboundHttpEnd);
    process.interaction = Some(wire::Interaction {
        kind: wire::InteractionKind::Process as i32,
        driver: "node".to_string(),
        method: "spawn".to_string(),
        status_code: 200,
        port: 443,
        ..wire::Interaction::default()
    });

    let exception_payload = wire::ExceptionPayload {
        exception_type: "app.NotFoundException".to_string(),
        sanitized_message: "owner not found".to_string(),
        stack_frames: Vec::new(),
    };

    vec![
        (
            "recording-values-all-states",
            "FRAME_ENTER with one binding in each of the five CapturedValue states, roles and name origins",
            envelope(10, batch(vec![all_states])),
            json!({"events": 1, "bindings": [
                {"name":"id","role":"argument","nameOrigin":"declared","state":"captured"},
                {"name":"password","role":"argument","nameOrigin":"declared","state":"redacted"},
                {"name":"arg2","role":"argument","nameOrigin":"synthesized","state":"truncated"},
                {"name":"this","role":"receiver","nameOrigin":"declared","state":"unavailable","reason":"focused_capture_not_armed"},
                {"name":"extra","role":"argument","nameOrigin":"declared","state":"dropped","reason":"value_budget"}],
                "sourceBinding": "observed_unattested"}),
        ),
        (
            "recording-line-cursor",
            "LINE_CURSOR (kind 5): start_line == end_line, OBSERVED_UNATTESTED binding, 32-byte content hash",
            envelope(11, batch(vec![line])),
            json!({"kind": 5, "startLine": 41, "endLine": 41, "sourceBinding": "observed_unattested", "contentHashBytes": 32}),
        ),
        (
            "recording-gap-coalesced",
            "GAP (kind 14) carrying GapPayload{LINE_BUDGET, count 7, seq 5..11}",
            envelope(12, batch(vec![gap])),
            json!({"kind": 14, "gap": {"reason": "line_budget", "count": 7, "firstRecordingSeq": 5, "lastRecordingSeq": 11}}),
        ),
        (
            "recording-interaction-additions",
            "Interaction fields 11-15 (statement_kind, tables, sanitized_shape, port, status_code) and INTERACTION_KIND_PROCESS",
            envelope(13, batch(vec![interaction, process])),
            json!({"events": 2, "first": {"statementKind": "select", "tables": ["owners","pets"], "port": 5432},
                   "second": {"kind": "process", "driver": "node", "method": "spawn", "statusCode": 200, "port": 443}}),
        ),
        (
            "recording-finished-outcome-responded",
            "RecordingFinished.outcome = RESPONDED with HTTP status 200",
            envelope(
                14,
                Payload::RecordingFinished(finished(Some(wire::RecordingOutcome {
                    kind: wire::OutcomeKind::Responded as i32,
                    http_status: 200,
                    exception: None,
                    thrown_from_event_id: String::new(),
                }))),
            ),
            json!({"outcome": {"kind": "responded", "httpStatus": 200}}),
        ),
        (
            "recording-finished-outcome-exception",
            "RecordingFinished.outcome = EXCEPTION_PROPAGATED with exception payload and throwing frame id",
            envelope(
                15,
                Payload::RecordingFinished(finished(Some(wire::RecordingOutcome {
                    kind: wire::OutcomeKind::ExceptionPropagated as i32,
                    http_status: 500,
                    exception: Some(exception_payload),
                    thrown_from_event_id: "e-3".to_string(),
                }))),
            ),
            json!({"outcome": {"kind": "exception_propagated", "httpStatus": 500, "exceptionType": "app.NotFoundException", "thrownFromEventId": "e-3"}}),
        ),
        (
            "recording-finished-outcome-unobserved",
            "RecordingFinished.outcome = UNOBSERVED (http_status must be 0)",
            envelope(
                16,
                Payload::RecordingFinished(finished(Some(wire::RecordingOutcome {
                    kind: wire::OutcomeKind::Unobserved as i32,
                    ..wire::RecordingOutcome::default()
                }))),
            ),
            json!({"outcome": {"kind": "unobserved", "httpStatus": 0}}),
        ),
        (
            "capture-command-arm-focused",
            "ARM_FOCUSED_CAPTURE with max_line_events (8), max_value_bytes (9), include_locals (10) and package_filters",
            envelope(
                17,
                Payload::CaptureCommand(wire::CaptureCommand {
                    command_seq: 1,
                    kind: wire::CaptureCommandKind::ArmFocusedCapture as i32,
                    operation_ids: Vec::new(),
                    package_filters: vec!["com.example.petclinic".to_string()],
                    max_match_count: 3,
                    expiry_monotonic_ns: 0,
                    approval_ref: "run-1".to_string(),
                    max_line_events: 8192,
                    max_value_bytes: 4_194_304,
                    include_locals: true,
                }),
            ),
            json!({"maxLineEvents": 8192, "maxValueBytes": 4194304, "includeLocals": true, "packageFilters": ["com.example.petclinic"]}),
        ),
        (
            "recording-started-standard-policy",
            "RecordingStarted with capture_policy_id xtrace.standard.v1",
            envelope(18, Payload::RecordingStarted(started("xtrace.standard.v1", ""))),
            json!({"capturePolicyId": "xtrace.standard.v1"}),
        ),
        (
            "recording-started-focused-policy",
            "RecordingStarted with capture_policy_id xtrace.focused.v1",
            envelope(19, Payload::RecordingStarted(started("xtrace.focused.v1", ""))),
            json!({"capturePolicyId": "xtrace.focused.v1"}),
        ),
        (
            "recording-exercise-item",
            "RecordingStarted.exercise_item_id (field 14) copied from X-XTrace-Exercise-Item",
            envelope(
                20,
                Payload::RecordingStarted(started(
                    "xtrace.standard.v1",
                    "6f1c1d0e-8b8e-4c52-9a43-0f6f2d9b7a10",
                )),
            ),
            json!({"exerciseItemId": "6f1c1d0e-8b8e-4c52-9a43-0f6f2d9b7a10"}),
        ),
        (
            "adapter-hello-runtime-facts",
            "AdapterHello.runtime_facts (field 17), adapter-reported and outside the HMAC transcript",
            envelope(
                21,
                Payload::AdapterHello(wire::AdapterHello {
                    adapter_name: "xtrace-java-agent".to_string(),
                    adapter_version: "0.0.1".to_string(),
                    runtime_facts: Some(wire::RuntimeFacts {
                        framework: "spring-boot".to_string(),
                        framework_version: "3.3.4".to_string(),
                        module_system: "fatjar".to_string(),
                        launch_mode: "direct".to_string(),
                        capture_depth: "standard".to_string(),
                        node_mode: String::new(),
                        package_manager: String::new(),
                    }),
                    ..wire::AdapterHello::default()
                }),
            ),
            json!({"runtimeFacts": {"framework": "spring-boot", "launchMode": "direct", "captureDepth": "standard"}}),
        ),
    ]
}

fn render(description: &str, summary: &Value, env: &wire::AgentEnvelope) -> String {
    let doc = json!({
        "description": description,
        "message": "xtp.agent.v1.AgentEnvelope",
        "summary": summary,
        "bytes_hex": hex(&env.encode_to_vec()),
    });
    let mut text = serde_json::to_string_pretty(&doc).expect("render fixture");
    text.push('\n');
    text
}

#[test]
fn golden_envelopes_decode_and_reencode_byte_identical() {
    let regen = fixture_dir().join(".regen").exists();
    for (name, description, env, summary) in cases() {
        let path = fixture_dir().join(format!("{name}.json"));
        if regen {
            fs::write(&path, render(description, &summary, &env)).expect("write fixture");
        }
        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
        let doc: Value = serde_json::from_str(&text).expect("fixture json");
        let bytes = unhex(doc["bytes_hex"].as_str().expect("bytes_hex"));
        let decoded = wire::AgentEnvelope::decode(bytes.as_slice()).expect("decode fixture");
        assert_eq!(decoded, env, "{name}: decoded fixture differs from the Rust definition");
        assert_eq!(decoded.encode_to_vec(), bytes, "{name}: re-encode is not byte identical");
        assert_eq!(text, render(description, &summary, &env), "{name}: fixture file is stale");
    }
}

#[test]
fn golden_envelopes_decode_in_rust_java_node() {
    // Rust asserts here; Java and Node assert against the same files in their own test paths.
    for (name, _, env, _) in cases() {
        let doc: Value = serde_json::from_str(
            &fs::read_to_string(fixture_dir().join(format!("{name}.json"))).expect("fixture"),
        )
        .expect("json");
        let bytes = unhex(doc["bytes_hex"].as_str().expect("hex"));
        let decoded = wire::AgentEnvelope::decode(bytes.as_slice()).expect("decode");
        assert_eq!(decoded.payload, env.payload, "{name}");
    }
}

// ---- descriptor reflection ------------------------------------------------------------------

#[derive(Clone, PartialEq, prost::Message)]
struct FileDescriptorSet {
    #[prost(message, repeated, tag = "1")]
    file: Vec<FileDescriptorProto>,
}
#[derive(Clone, PartialEq, prost::Message)]
struct FileDescriptorProto {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(message, repeated, tag = "4")]
    message_type: Vec<DescriptorProto>,
    #[prost(message, repeated, tag = "5")]
    enum_type: Vec<EnumDescriptorProto>,
}
#[derive(Clone, PartialEq, prost::Message)]
struct DescriptorProto {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(message, repeated, tag = "2")]
    field: Vec<FieldDescriptorProto>,
}
#[derive(Clone, PartialEq, prost::Message)]
struct FieldDescriptorProto {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(int32, optional, tag = "3")]
    number: Option<i32>,
    #[prost(int32, optional, tag = "4")]
    label: Option<i32>,
    #[prost(int32, optional, tag = "5")]
    field_type: Option<i32>,
    #[prost(string, optional, tag = "6")]
    type_name: Option<String>,
}
#[derive(Clone, PartialEq, prost::Message)]
struct EnumDescriptorProto {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(message, repeated, tag = "2")]
    value: Vec<EnumValueDescriptorProto>,
}
#[derive(Clone, PartialEq, prost::Message)]
struct EnumValueDescriptorProto {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(int32, optional, tag = "2")]
    number: Option<i32>,
}

const LABEL_REPEATED: i32 = 3;

fn descriptor() -> FileDescriptorSet {
    FileDescriptorSet::decode(
        &include_bytes!(concat!(env!("OUT_DIR"), "/generated/file_descriptor_set.bin"))[..],
    )
    .expect("decode descriptor set")
}

fn scalar_name(code: i32) -> Option<&'static str> {
    Some(match code {
        1 => "double",
        2 => "float",
        3 => "int64",
        4 => "uint64",
        5 => "int32",
        6 => "fixed64",
        7 => "fixed32",
        8 => "bool",
        9 => "string",
        12 => "bytes",
        13 => "uint32",
        _ => return None,
    })
}

/// (message, number, name, type, repeated)
type FieldRow = (String, i32, String, String, bool);

fn all_fields(set: &FileDescriptorSet) -> BTreeSet<FieldRow> {
    let mut rows = BTreeSet::new();
    for file in &set.file {
        for message in &file.message_type {
            let mname = message.name.clone().unwrap_or_default();
            for field in &message.field {
                let ty = if let Some(s) = scalar_name(field.field_type.unwrap_or(0)) {
                    s.to_string()
                } else {
                    let full = field.type_name.clone().unwrap_or_default();
                    let last = full.rsplit('.').next().unwrap_or("").to_string();
                    if last.ends_with("Entry") { "map".to_string() } else { last }
                };
                let repeated = field.label == Some(LABEL_REPEATED) && ty != "map";
                rows.insert((
                    mname.clone(),
                    field.number.unwrap_or(0),
                    field.name.clone().unwrap_or_default(),
                    ty,
                    repeated,
                ));
            }
        }
    }
    rows
}

fn all_enum_values(set: &FileDescriptorSet) -> BTreeSet<(String, i32, String)> {
    let mut rows = BTreeSet::new();
    for file in &set.file {
        for e in &file.enum_type {
            for v in &e.value {
                rows.insert((
                    e.name.clone().unwrap_or_default(),
                    v.number.unwrap_or(0),
                    v.name.clone().unwrap_or_default(),
                ));
            }
        }
    }
    rows
}

#[test]
fn proto_baseline_fields_still_present() {
    let snapshot: Value = serde_json::from_str(
        &fs::read_to_string(fixture_dir().join("baseline-fields-a181a0c.json")).expect("baseline"),
    )
    .expect("baseline json");
    let set = descriptor();
    let fields = all_fields(&set);
    let enums = all_enum_values(&set);
    let mut checked = 0;
    for row in snapshot["fields"].as_array().expect("fields") {
        let r = row.as_array().expect("row");
        let want: FieldRow = (
            r[0].as_str().expect("msg").to_string(),
            i32::try_from(r[1].as_i64().expect("num")).expect("i32"),
            r[2].as_str().expect("name").to_string(),
            r[3].as_str().expect("type").to_string(),
            r[4].as_bool().expect("repeated"),
        );
        assert!(fields.contains(&want), "baseline field removed or changed: {want:?}");
        checked += 1;
    }
    for row in snapshot["enum_values"].as_array().expect("enums") {
        let r = row.as_array().expect("row");
        let want = (
            r[0].as_str().expect("enum").to_string(),
            i32::try_from(r[1].as_i64().expect("num")).expect("i32"),
            r[2].as_str().expect("name").to_string(),
        );
        assert!(enums.contains(&want), "baseline enum value removed or changed: {want:?}");
        checked += 1;
    }
    assert!(checked > 200, "baseline snapshot unexpectedly small: {checked}");
}

fn field(set: &FileDescriptorSet, message: &str, name: &str) -> i32 {
    all_fields(set)
        .into_iter()
        .find(|(m, _, n, _, _)| m == message && n == name)
        .unwrap_or_else(|| panic!("missing {message}.{name}"))
        .1
}

fn enum_value(set: &FileDescriptorSet, enum_name: &str, value_name: &str) -> i32 {
    all_enum_values(set)
        .into_iter()
        .find(|(e, _, n)| e == enum_name && n == value_name)
        .unwrap_or_else(|| panic!("missing {enum_name}.{value_name}"))
        .1
}

#[test]
fn proto_field_numbers_match_adr_0003() {
    let set = descriptor();
    // ADR 0003 section 4.
    assert_eq!(field(&set, "RecordingEvent", "bindings"), 14);
    assert_eq!(field(&set, "RecordingEvent", "gap"), 15);
    assert_eq!(field(&set, "RecordingFinished", "outcome"), 8);
    assert_eq!(field(&set, "CaptureCommand", "max_line_events"), 8);
    assert_eq!(field(&set, "CaptureCommand", "max_value_bytes"), 9);
    assert_eq!(field(&set, "CaptureCommand", "include_locals"), 10);
    assert_eq!(enum_value(&set, "SourceBinding", "SOURCE_BINDING_OBSERVED_UNATTESTED"), 6);
    assert_eq!(enum_value(&set, "SourceBinding", "SOURCE_BINDING_SOURCE_MAP_ABSENT"), 7);
    assert_eq!(enum_value(&set, "SourceBinding", "SOURCE_BINDING_SOURCE_MAP_UNRESOLVED"), 8);
    assert_eq!(
        enum_value(&set, "UnavailableReason", "UNAVAILABLE_REASON_FOCUSED_CAPTURE_NOT_ARMED"),
        6
    );
    assert_eq!(enum_value(&set, "UnavailableReason", "UNAVAILABLE_REASON_UNSAFE_TO_RENDER"), 7);
    assert_eq!(
        enum_value(&set, "UnavailableReason", "UNAVAILABLE_REASON_CLASS_NOT_TRANSFORMABLE"),
        8
    );
    assert_eq!(enum_value(&set, "DropReason", "DROP_REASON_THROTTLE_SUPPRESSED"), 5);
    assert_eq!(enum_value(&set, "DropReason", "DROP_REASON_LINE_BUDGET"), 6);
    assert_eq!(enum_value(&set, "DropReason", "DROP_REASON_VALUE_BUDGET"), 7);
    for (i, name) in [
        "GAP_REASON_LINE_BUDGET",
        "GAP_REASON_VALUE_BUDGET",
        "GAP_REASON_THROTTLE",
        "GAP_REASON_QUEUE_FULL",
        "GAP_REASON_CORRELATION_LOST",
        "GAP_REASON_CLASS_NOT_TRANSFORMED",
        "GAP_REASON_MODULE_LOADED_BEFORE_ARM",
        "GAP_REASON_SOURCE_MAP_ABSENT",
        "GAP_REASON_HANDLED_EXCEPTION_UNOBSERVED",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(enum_value(&set, "GapReason", name), i32::try_from(i + 1).expect("small"));
    }
    for (i, name) in [
        "OUTCOME_KIND_RESPONDED",
        "OUTCOME_KIND_EXCEPTION_PROPAGATED",
        "OUTCOME_KIND_CLIENT_ABORTED",
        "OUTCOME_KIND_UNOBSERVED",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(enum_value(&set, "OutcomeKind", name), i32::try_from(i + 1).expect("small"));
    }
    // ADR 0003 addendum (OPEN-15, additive beyond the ADR).
    assert_eq!(enum_value(&set, "GapReason", "GAP_REASON_CHILD_PROCESS_NOT_INSTRUMENTED"), 10);
    assert_eq!(enum_value(&set, "GapReason", "GAP_REASON_BOOTSTRAP_CONSUMED"), 11);
    assert_eq!(enum_value(&set, "InteractionKind", "INTERACTION_KIND_PROCESS"), 6);
    assert_eq!(field(&set, "RecordingStarted", "exercise_item_id"), 14);
    assert_eq!(field(&set, "Interaction", "statement_kind"), 11);
    assert_eq!(field(&set, "Interaction", "tables"), 12);
    assert_eq!(field(&set, "Interaction", "sanitized_shape"), 13);
    assert_eq!(field(&set, "Interaction", "port"), 14);
    assert_eq!(field(&set, "Interaction", "status_code"), 15);
    assert_eq!(field(&set, "AdapterHello", "runtime_facts"), 17);
    assert_eq!(field(&set, "ValueBinding", "value"), 4);
    assert_eq!(field(&set, "GapPayload", "last_recording_seq"), 4);
    assert_eq!(field(&set, "RecordingOutcome", "thrown_from_event_id"), 4);
}
