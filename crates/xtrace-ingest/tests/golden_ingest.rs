//! Crosses the golden wire fixtures (`schema/fixtures/xtp-agent`) with the ingest validator: every
//! recording event, start marker and finish marker the fixtures carry must be accepted, because
//! adapters are told to copy them. (The protocol crate cannot depend on ingest, so this lives here.)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration tests assert on fixture data and fail by panicking"
)]

use std::fs;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use prost::Message as _;
use xtrace_domain::{CaptureMode, RecordingId};
use xtrace_ingest::event_rules::{validate_event, validate_finished};
use xtrace_ingest::{IngestConfig, IngestValidator};
use xtrace_protocol::generated::agent::AgentEnvelope;
use xtrace_protocol::generated::agent::agent_envelope::Payload;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schema/fixtures/xtp-agent")
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn envelopes() -> Vec<(String, AgentEnvelope)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(fixture_dir()).expect("fixture dir") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let doc: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("json");
        let Some(hex) = doc.get("bytes_hex").and_then(|v| v.as_str()) else {
            continue; // handshake vector and baseline snapshot are not envelopes
        };
        let envelope = AgentEnvelope::decode(unhex(hex).as_slice()).expect("decode");
        out.push((path.file_name().unwrap().to_string_lossy().into_owned(), envelope));
    }
    assert!(out.len() >= 10, "expected the golden envelope set, found {}", out.len());
    out
}

#[test]
fn every_golden_recording_payload_passes_ingest_validation() {
    let mut events = 0;
    let mut finished = 0;
    let mut started = 0;
    for (name, envelope) in envelopes() {
        match envelope.payload.expect("payload") {
            Payload::EventBatch(batch) => {
                for event in &batch.events {
                    // Focused with the audit active is the widest rule set the fixtures target.
                    validate_event(event, CaptureMode::Focused, true).unwrap_or_else(|e| {
                        panic!("{name}: event {} rejected: {e}", event.recording_seq)
                    });
                    events += 1;
                }
            }
            Payload::RecordingFinished(marker) => {
                let id = RecordingId::from_uuid(
                    uuid::Uuid::from_slice(&marker.recording_id).expect("uuid bytes"),
                );
                validate_finished(&marker, id)
                    .unwrap_or_else(|e| panic!("{name}: finish rejected: {e}"));
                finished += 1;
            }
            Payload::RecordingStarted(marker) => {
                let mode = CaptureMode::from_policy_id(&marker.capture_policy_id);
                let mut validator =
                    IngestValidator::new(IngestConfig::mode_derived(NonZeroUsize::MIN));
                validator
                    .accept_started(&marker, mode)
                    .unwrap_or_else(|e| panic!("{name}: start rejected: {e}"));
                started += 1;
            }
            _ => {}
        }
    }
    assert!(events > 0 && finished > 0 && started > 0, "{events}/{finished}/{started}");
}
