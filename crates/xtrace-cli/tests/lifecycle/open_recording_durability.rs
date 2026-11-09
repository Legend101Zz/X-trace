//! An acknowledged, unfinished loopback batch survives process interruption and lifecycle recovery.

use super::*;
use std::io::{BufRead as _, BufReader};
use xtrace_application::recording_queries::{
    RecordingCompletionEvidence, RecordingReadPort as _, RecordingStatus, ShowWindowRequest,
};
use xtrace_store::SqliteRecordingReader;

// Use the same real pinned-TLS adapter transport as the lifecycle synthetic client.
// Leave both the request and the connection open after its batch acknowledgement.
const UNFINISHED_CLIENT: &str = r#"
import { resolve } from 'node:path';
import { create } from '@bufbuild/protobuf';
import { parse, v7 } from 'uuid';
import { openXtpSession, readBootstrap } from '@xtrace/adapter-core';
import {
  EventBatchSchema, RecordingEventSchema, RecordingEventKind, RecordingStartedSchema,
} from '@xtrace/protocol';

const bootstrap = await readBootstrap(process.argv[1]);
const session = await openXtpSession(bootstrap, resolve('fixtures/synthetic-manifest.json'), {
  adapterName: 'xtrace-node-synthetic-client', adapterVersion: '0.0.1',
  language: 'node', runtimeName: 'node', runtimeVersion: process.version,
  pid: BigInt(process.pid), processStartMonotonicNs: process.hrtime.bigint(),
});
const recordingId = v7();
const bytes = Buffer.from(parse(recordingId));
async function send(messageId, payload, highest) {
  const ack = await session.send(messageId, payload, recordingId);
  if (ack.case !== 'ack' || ack.value.rejected.length !== 0 ||
      ack.value.highestContiguousRecordingSeq[recordingId] !== highest) {
    throw new Error('unfinished batch was not acknowledged');
  }
}
await send('unfinished-start', {
  case: 'recordingStarted', value: create(RecordingStartedSchema, {
    recordingId: bytes, recordingSeq: 1n, method: 'GET', matchedRouteTemplate: '/waiting',
  }),
}, 1n);
await send('unfinished-batch', {
  case: 'eventBatch', value: create(EventBatchSchema, {
    recordingId: bytes, events: [
      create(RecordingEventSchema, {
        eventId: 'unfinished-enter', recordingSeq: 2n, monotonicNs: 10n,
        kind: RecordingEventKind.FRAME_ENTER, symbol: 'waiting.handler',
      }),
      create(RecordingEventSchema, {
        eventId: 'unfinished-child', parentEventId: 'unfinished-enter',
        recordingSeq: 3n, monotonicNs: 11n,
        kind: RecordingEventKind.FRAME_ENTER, symbol: 'waiting.child',
      }),
    ],
  }),
}, 3n);
process.stdout.write(JSON.stringify({ recording_id: recordingId }) + '\n');
process.stdin.resume();
await new Promise(resolve => process.stdin.once('end', resolve));
await session.close();
"#;

fn unfinished_client(bootstrap: &Path) -> (ChildGuard, RecordingId) {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut client = ChildGuard(Some(
        Command::new("node")
            .args(["--input-type=module", "-e", UNFINISHED_CLIENT])
            .arg(bootstrap)
            .current_dir(workspace.join("adapters/node"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn unfinished loopback client"),
    ));
    let stdout = client.0.as_mut().expect("client").stdout.take().expect("client stdout");
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line);
        let _ = send.send((result, line));
    });
    let (result, line) = receive
        .recv_timeout(Duration::from_secs(5))
        .expect("batch acknowledgement within the loopback harness budget");
    result.expect("read acknowledged batch receipt");
    reader.join().expect("receipt reader");
    let receipt: Value = serde_json::from_str(&line).expect("acknowledged batch JSON");
    let recording_id = receipt["recording_id"]
        .as_str()
        .expect("recording id")
        .parse()
        .expect("typed recording id");
    (client, recording_id)
}

fn assert_readable(fx: &Fixture, recording_id: RecordingId, recovered: bool) {
    // Open an independent store handle: volatile capture state cannot satisfy this read.
    let store = SqliteStore::open(
        &fx.project_root().join("metadata.sqlite3"),
        OpenOptions::default().with_must_exist(true),
    )
    .expect("open persisted recording independently");
    let reader = SqliteRecordingReader::new(store, fx.project_root());
    let window = reader
        .show_recording(&ShowWindowRequest {
            project_id: fx.project_id.parse().expect("project id"),
            recording_id,
            limit: 10,
            after_sequence: None,
        })
        .expect("read API opens the unfinished batch");
    assert_eq!(
        window.status,
        if recovered { RecordingStatus::Partial } else { RecordingStatus::Recording }
    );
    assert_eq!(
        window.completion,
        if recovered {
            RecordingCompletionEvidence::Partial
        } else {
            RecordingCompletionEvidence::Unavailable
        }
    );
    assert!(window.duration_ns.is_none(), "no finish duration was observed");
    if !recovered {
        assert_eq!(window.segment_count, "0");
        assert!(window.events.is_empty(), "the durable journal is projected on recovery");
        assert!(
            window.incomplete_evidence.iter().any(|reason| reason == "durable_tail_pending:2..3")
        );
        let (recordings, _) = reader
            .list_recordings(fx.project_id.parse().expect("project id"), None, 10)
            .expect("journal-aware recovery metadata");
        let recording = recordings
            .iter()
            .find(|item| item.recording_id == recording_id)
            .expect("open recording");
        assert_eq!(recording.event_count, "2");
        assert_eq!(recording.last_sequence.as_deref(), Some("3"));
        return;
    }
    assert_eq!(window.segment_count, "1");
    assert_eq!(window.events.len(), 2);
    assert_eq!(window.events[0].sequence, "2");
    assert_eq!(window.events[1].sequence, "3");
    assert_eq!(window.events[0].event_id.as_deref(), Some("unfinished-enter"));
    assert_eq!(window.events[1].event_id.as_deref(), Some("unfinished-child"));
    assert!(window.events[0].frame_id.is_some());
    assert_eq!(window.events[1].parent_frame_id, window.events[0].frame_id);
}

#[test]
fn acknowledged_unfinished_batch_survives_interruption_then_stop_and_restart() {
    recovery_journey(true);
}

#[test]
fn acknowledged_unfinished_batch_survives_interruption_then_restart_directly() {
    recovery_journey(false);
}

fn recovery_journey(stop_first: bool) {
    let fx = fixture();
    let started = fx.ok_json(&["record"]);
    let pid = fx.track(started["pid"].as_u64().expect("daemon pid"));
    let bootstrap = Path::new(started["bootstrap_path"].as_str().expect("bootstrap"));
    let (mut client, recording_id) = unfinished_client(bootstrap);
    assert_readable(&fx, recording_id, false);
    // Interrupt both producer and daemon without Finish or a graceful flush.
    let mut child = client.0.take().expect("client");
    child.kill().expect("interrupt the client this test spawned");
    child.wait().expect("reap interrupted client");
    let killed =
        Command::new("kill").args(["-KILL", &pid.to_string()]).status().expect("kill daemon");
    assert!(killed.success());
    wait_gone(pid);
    assert_readable(&fx, recording_id, false);

    if stop_first {
        let stopped = fx.xtrace(&["stop"]);
        assert_eq!(stopped.status.code(), Some(3), "stop reports no running daemon");
        let doc: Value = serde_json::from_slice(&stopped.stdout).expect("stop recovery document");
        assert_recovery(&doc, recording_id);
        assert_readable(&fx, recording_id, true);
    }
    let restarted = fx.ok_json(&["restart"]);
    assert_eq!(restarted["previously_running"], false);
    fx.track(restarted["started"]["pid"].as_u64().expect("restarted daemon pid"));
    if stop_first {
        assert_eq!(restarted["stopped"]["recovered_recordings"], serde_json::json!([]));
    } else {
        assert_recovery(&restarted["stopped"], recording_id);
    }
    assert_readable(&fx, recording_id, true);
    let shown = fx.ok_json(&["recording", "show", &recording_id.to_string()]);
    assert_eq!(shown["completion"], "partial");
    assert_eq!(shown["events"].as_array().expect("CLI read API events").len(), 2);
    fx.ok_json(&["stop"]);
}

fn assert_recovery(doc: &Value, recording_id: RecordingId) {
    let recovered = doc["recovered_recordings"].as_array().expect("recovered recordings");
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0]["recording_id"], recording_id.to_string());
    assert_eq!(recovered[0]["completion"], "partial");
}
