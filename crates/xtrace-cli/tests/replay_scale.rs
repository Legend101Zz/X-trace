//! Synthetic 10,000-frame correctness fixture. No real-application or performance claim.

#![cfg(unix)]
#![allow(missing_docs, reason = "integration test symbols are executable fixtures")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "assertions on a new synthetic private project"
)]

use std::collections::HashSet;
use xtrace_application::recording::STANDARD_EVENT_CAP;
use xtrace_application::recording_queries::{
    MAX_RECORDING_EVENT_PROJECTION_BYTES, NavigationResult, RecordingCompletionEvidence,
    RecordingDetail, RecordingQueryService, RecordingStatus, ShowRecording,
};
use xtrace_domain::CorrelationId;
use xtrace_protocol::generated::agent::RecordingEventKind;
use xtrace_store::{OpenOptions, SqliteRecordingReader, SqliteStore};

#[path = "support/replay_scale.rs"]
mod fixture;

const PAGE_LIMIT: u32 = 200;

fn assert_terminal(page: &RecordingDetail) {
    assert_eq!(page.status, RecordingStatus::Complete);
    assert_eq!(page.completion, RecordingCompletionEvidence::Complete);
    assert!(page.incomplete_evidence.is_empty());
    assert!(page.duration_ns.is_none(), "synthetic fixture declares no measured duration");
    assert!(page.drop_counts_by_priority.is_empty());
    let capacity = page.capacity.as_ref().expect("durable terminal capacity evidence");
    assert_eq!(capacity.event_cap as usize, STANDARD_EVENT_CAP);
    assert_eq!(capacity.event_count, fixture::FRAME_COUNT);
    assert_eq!(capacity.capacity_dropped_events, "0");
    assert!(capacity.drops_by_priority.is_empty());
}

#[test]
fn synthetic_ten_thousand_frames_are_complete_ordered_and_navigable() {
    let fixture = fixture::SyntheticScaleProject::seed();
    let mut cursor = None;
    let mut cursors = HashSet::new();
    let mut identities = HashSet::new();
    let mut frames = Vec::new();
    let mut previous_frame = None;
    let mut previous_next = None;
    let mut first_window_size = 0;
    let mut pages = 0;
    loop {
        let page = fixture.show(cursor.as_deref(), PAGE_LIMIT);
        assert_terminal(&page);
        assert_eq!(page.project_id, fixture.project_id);
        assert_eq!(page.recording_id, fixture.recording_id);
        assert_eq!(page.limit, PAGE_LIMIT);
        assert_eq!(page.cursor, cursor);
        assert!(!page.events.is_empty(), "cursor must make progress");
        assert!(page.events.len() <= PAGE_LIMIT as usize);
        let projection_bytes = page.events.iter().fold(2, |bytes, event| {
            bytes + event.serialized_size_with_separator().expect("projected event width")
        });
        assert!(projection_bytes <= MAX_RECORDING_EVENT_PROJECTION_BYTES);
        if pages == 0 {
            first_window_size = page.events.len();
            assert!(first_window_size >= fixture::CALL_SHAPE.len(), "first call shape fits");
            let root = page.events[0].frame_id.expect("first synthetic request");
            let siblings: Vec<_> = page
                .events
                .iter()
                .filter(|event| {
                    event.parent_frame_id == Some(root)
                        && event.kind == "recording_event_kind:frame_enter"
                })
                .filter_map(|event| event.symbol.as_deref())
                .collect();
            assert_eq!(
                siblings,
                [
                    "SyntheticReplayScale.validate",
                    "SyntheticReplayScale.repository",
                    "SyntheticReplayScale.render"
                ]
            );
            assert_eq!(page.events[3].depth, Some(3), "bounded multilevel fixture topology");
        }
        pages += 1;
        assert!(pages <= fixture::FRAME_COUNT, "bounded traversal must terminate");
        for event in &page.events {
            let index = frames.len();
            let shape_index = index % fixture::CALL_SHAPE.len();
            let (symbol, kind, parent_offset, depth) = fixture::CALL_SHAPE[shape_index];
            let sequence = frames.len() as u64 + 2;
            assert_eq!(event.sequence, sequence.to_string());
            assert_eq!(
                event.event_id.as_deref(),
                Some(format!("synthetic-scale-{sequence:05}").as_str())
            );
            assert_eq!(event.symbol.as_deref(), Some(symbol));
            assert_eq!(
                event.kind,
                match kind {
                    RecordingEventKind::FrameEnter => "recording_event_kind:frame_enter",
                    RecordingEventKind::FrameExit => "recording_event_kind:frame_exit",
                    _ => panic!("synthetic shape only contains call entries and exits"),
                }
            );
            let parent_index = parent_offset.map(|parent| index - shape_index + parent);
            assert_eq!(event.parent_frame_id, parent_index.map(|parent| frames[parent]));
            assert_eq!(
                event.parent_event_id,
                parent_index.map(|parent| format!("synthetic-scale-{:05}", parent + 2))
            );
            assert_eq!(event.depth, Some(depth));
            assert!(event.line.is_none(), "an entry cannot invent an active line");
            let frame_id = event.frame_id.expect("durable navigable frame identity");
            assert!(identities.insert(frame_id), "every recorded frame identity is distinct");
            assert_eq!(
                event.navigation.previous,
                previous_frame.map_or(NavigationResult::Boundary, |frame_id| {
                    NavigationResult::Target { frame_id }
                })
            );
            if let Some(next) = previous_next {
                assert_eq!(next, NavigationResult::Target { frame_id });
            }
            previous_frame = Some(frame_id);
            previous_next = Some(event.navigation.next);
            frames.push(frame_id);
            assert!(frames.len() <= fixture::FRAME_COUNT as usize, "no surplus frames");
        }
        cursor = page.next_cursor;
        if let Some(next) = &cursor {
            assert!(cursors.insert(next.clone()), "continuation cursors cannot cycle");
        } else {
            break;
        }
    }
    assert_eq!(frames.len(), fixture::FRAME_COUNT as usize);
    assert_eq!(identities.len(), fixture::FRAME_COUNT as usize);
    assert_eq!(previous_next, Some(NavigationResult::Boundary));

    // Reopen independently, as the viewer does; no writer-side state can satisfy this read.
    let root = fixture.project_root();
    let store = SqliteStore::open(
        &root.join("metadata.sqlite3"),
        OpenOptions::default().with_must_exist(true),
    )
    .expect("reopen seeded store for viewer read use case");
    let query = RecordingQueryService::new(SqliteRecordingReader::new(store, root));
    let anchor_index = frames.len() - 3;
    let anchor = frames[anchor_index];
    let around = query
        .show(
            ShowRecording {
                project_id: fixture.project_id,
                recording_id: fixture.recording_id,
                limit: PAGE_LIMIT,
                cursor: None,
                around_frame: Some(anchor),
            },
            CorrelationId::new(),
        )
        .expect("viewer aroundFrame near tail");
    assert_terminal(&around);
    assert_eq!(around.anchor_frame_id, Some(anchor));
    assert!(around.events.len() <= PAGE_LIMIT as usize);
    assert!(around.next_cursor.is_none(), "near-tail window reaches the verified end");
    let start = anchor_index - PAGE_LIMIT as usize / 2;
    let around_ids: Vec<_> = around.events.iter().map(|event| event.frame_id.unwrap()).collect();
    assert!(around_ids == frames[start..], "near-tail identities must match prior CLI order");
    assert_eq!(around.events[PAGE_LIMIT as usize / 2].frame_id, Some(anchor));
    assert_eq!(around.first_sequence, Some((start + 2).to_string()));
    assert_eq!(around.last_sequence, Some((u64::from(fixture::FRAME_COUNT) + 1).to_string()));
    let navigation = query
        .frame_navigation(fixture.project_id, fixture.recording_id, anchor, CorrelationId::new())
        .expect("indexed navigation endpoint use case near tail");
    assert_eq!(navigation.frame_id, anchor);
    assert_eq!(navigation.sequence, (anchor_index + 2).to_string());
    assert_eq!(
        navigation.navigation.previous,
        NavigationResult::Target { frame_id: frames[anchor_index - 1] }
    );
    assert_eq!(
        navigation.navigation.next,
        NavigationResult::Target { frame_id: frames[anchor_index + 1] }
    );

    fixture.retain_if_requested();

    // Only aggregates reach hosted stdout. Paths and synthetic event bodies stay private.
    println!(
        "synthetic_replay_scale: verified_frames={} first_window_size={} pages={} around_tail_frames={} complete=true capacity_drops=0 performance_claim=false",
        frames.len(),
        first_window_size,
        pages,
        around.events.len()
    );
}
