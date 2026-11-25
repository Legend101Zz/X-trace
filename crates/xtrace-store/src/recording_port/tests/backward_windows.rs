//! Backward windows use persisted event order, including non-navigable and frame-less events.

use super::*;
use xtrace_application::recording_queries::{RecordingDetail, RecordingQueryService};

fn show(
    persisted: &Persisted,
    limit: u32,
    cursor: Option<String>,
    around_frame: Option<xtrace_domain::FrameId>,
) -> RecordingDetail {
    RecordingQueryService::new(SqliteRecordingReader::new(persisted.store.clone(), &persisted.root))
        .show(
            ShowRecording {
                project_id: persisted.project.id(),
                recording_id: persisted.recording_id,
                limit,
                cursor,
                around_frame,
            },
            CorrelationId::new(),
        )
        .expect("bounded verified window")
}

fn sequences(page: &RecordingDetail) -> Vec<u64> {
    page.events.iter().map(|event| event.sequence.parse().expect("sequence")).collect()
}

#[test]
fn backward_windows_round_trip_changed_limits_and_near_tail_anchors() {
    let events = (2..=26)
        .map(|sequence| {
            node(
                sequence,
                &format!("event-{sequence}"),
                "",
                if matches!(sequence, 8 | 14) { K_REQUEST_UPDATE } else { K_ENTER },
            )
        })
        .collect::<Vec<_>>();
    let persisted = persist(&events, 4, true);
    let ids = frame_ids(&window(&persisted, 50, None));
    let first = show(&persisted, 3, None, None);
    assert_eq!(sequences(&first), [2, 3, 4]);
    assert!(first.prev_cursor.is_none());
    let forward = first.next_cursor.expect("v1 forward cursor");
    assert!(forward.starts_with("v1."));
    let second = show(&persisted, 5, Some(forward), None);
    assert_eq!(sequences(&second), [5, 6, 7, 8, 9]);
    assert_eq!(
        second.events[3].frame_id,
        Some(ids[&8]),
        "sealed updates retain their index identity"
    );
    assert_eq!(second.events[3].navigation.previous, Nav::unavailable(Unav::NotNavigable));
    let previous = second.prev_cursor.expect("backward cursor");
    assert!(previous.starts_with("v2."));
    let back = show(&persisted, 2, Some(previous), None);
    assert_eq!(sequences(&back), [3, 4]);
    let again = show(&persisted, 5, back.next_cursor, None);
    assert_eq!(sequences(&again), [5, 6, 7, 8, 9]);

    // The anchor is three observed frames before the end. Its previous page is
    // addressed by the first returned event, independent of the anchor and limit.
    let near_tail = show(&persisted, 5, None, Some(ids[&23]));
    assert_eq!(sequences(&near_tail), [21, 22, 23, 24, 25]);
    assert!(near_tail.prev_cursor.is_some());
    let prior = show(&persisted, 3, near_tail.prev_cursor, None);
    assert_eq!(sequences(&prior), [18, 19, 20]);
    let prior = show(&persisted, 4, prior.prev_cursor, None);
    assert_eq!(sequences(&prior), [14, 15, 16, 17]);
    assert_eq!(prior.events[0].frame_id, Some(ids[&14]));
    assert_eq!(prior.events[0].navigation.next, Nav::unavailable(Unav::NotNavigable));
    let end = show(&persisted, 5, None, Some(ids[&26]));
    assert_eq!(sequences(&end), [24, 25, 26]);
    assert!(end.next_cursor.is_none());
    assert_eq!(sequences(&show(&persisted, 3, end.prev_cursor, None)), [21, 22, 23]);
    let head = show(&persisted, 5, None, Some(ids[&2]));
    assert!(head.prev_cursor.is_none());
}

#[test]
fn backward_windows_keep_nearest_suffix_when_projection_budget_shortens_page() {
    let events = (2..=801)
        .map(|sequence| {
            let mut item = node(sequence, &format!("event-{sequence}"), "", K_ENTER);
            item.payload.event.as_mut().expect("event").symbol = "s".repeat(220);
            item.canonical_bytes = item.payload.encode_to_vec();
            item
        })
        .collect::<Vec<_>>();
    let persisted = persist(&events, 800, false);
    // Use the direct read port only to resolve the anchor identity; the actual
    // pages and cursors below go through the public query service.
    let reader = SqliteRecordingReader::new(persisted.store.clone(), &persisted.root);
    let tail = reader
        .show_recording(&ShowWindowRequest {
            project_id: persisted.project.id(),
            recording_id: persisted.recording_id,
            limit: 1,
            after_sequence: Some(800),
            before_sequence: None,
        })
        .expect("verified tail frame");
    let anchor = tail.events[0].frame_id.expect("indexed frame");
    let end = show(&persisted, 1, None, Some(anchor));
    let back = show(&persisted, 1_000, end.prev_cursor, None);
    let values = sequences(&back);
    assert!(!values.is_empty());
    assert!(values.len() < 799, "projection budget shortens the backward page");
    assert_eq!(values.last(), Some(&800));
    assert_eq!(values, (*values.first().expect("first")..=800).collect::<Vec<_>>());
    assert!(back.prev_cursor.is_some());
    assert_eq!(sequences(&show(&persisted, 1, back.next_cursor, None)), [801]);
}

#[test]
fn backward_windows_fail_on_unreadable_immediate_predecessor_instead_of_skipping_it() {
    let persisted = persist(&tree(), 3, false);
    let ids = frame_ids(&window(&persisted, 50, None));
    let page = show(&persisted, 1, None, Some(ids[&8]));
    let token = page.prev_cursor.expect("previous window");
    // Sequence 7 is the immediate predecessor, in segment 1 (5..7). Alter the
    // immutable object without changing metadata: earlier readable objects must
    // never be substituted for the failed page.
    let raw: Vec<u8> = persisted.store.lock().expect("connection").query_row(
        "SELECT object_hash FROM recording_segments WHERE recording_id = ?1 AND segment_ordinal = 1",
        rusqlite::params![persisted.recording_id.as_uuid().as_bytes().to_vec()],
        |row| row.get(0),
    ).expect("predecessor object");
    let digest = raw.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let path = persisted
        .root
        .join("objects/b3")
        .join(&digest[..2])
        .join(format!("{}.xtf.zst", &digest[2..]));
    std::fs::write(&path, b"corrupt predecessor").expect("simulate unreadable object");
    let error = RecordingQueryService::new(SqliteRecordingReader::new(
        persisted.store.clone(),
        &persisted.root,
    ))
    .show(
        ShowRecording {
            project_id: persisted.project.id(),
            recording_id: persisted.recording_id,
            limit: 3,
            cursor: Some(token),
            around_frame: None,
        },
        CorrelationId::new(),
    )
    .expect_err("no silent skip");
    assert_eq!(error.category, xtrace_domain::ErrorCategory::Corruption);
}

#[test]
fn backward_windows_keep_nearest_suffix_when_verified_input_budget_shortens_page() {
    let events = (2..=71)
        .map(|sequence| {
            let mut item = node(sequence, &format!("event-{sequence}"), "", K_ENTER);
            item.payload.event.as_mut().expect("event").symbol = "x".repeat(350_000);
            item.canonical_bytes = item.payload.encode_to_vec();
            item
        })
        .collect::<Vec<_>>();
    let persisted = persist(&events, 10, false);
    let reader = SqliteRecordingReader::new(persisted.store.clone(), &persisted.root);
    let tail = reader
        .show_recording(&ShowWindowRequest {
            project_id: persisted.project.id(),
            recording_id: persisted.recording_id,
            limit: 1,
            after_sequence: Some(70),
            before_sequence: None,
        })
        .expect("verified tail frame");
    let end = show(&persisted, 1, None, Some(tail.events[0].frame_id.expect("tail frame")));
    let back = show(&persisted, 100, end.prev_cursor, None);
    let values = sequences(&back);
    assert_eq!(
        values,
        (32..=70).collect::<Vec<_>>(),
        "four logical segments fit; the anchor itself is excluded"
    );
    assert_eq!(sequences(&show(&persisted, 1, back.next_cursor, None)), [71]);
    let earlier = show(&persisted, 100, back.prev_cursor, None);
    assert_eq!(sequences(&earlier), (2..=31).collect::<Vec<_>>());
    assert!(earlier.prev_cursor.is_none());
}

#[test]
fn backward_windows_cross_the_verified_journal_and_sealed_prefix_without_gaps() {
    let all = tree();
    let persisted = persist(&all[..6], 3, false); // sealed sequences 2..7
    persisted
        .store
        .recording_store(&persisted.root)
        .expect("writer")
        .journal_tail(
            &PersistRecordingSegment {
                project_id: persisted.project.id(),
                recording_id: persisted.recording_id,
                segment_ordinal: 2,
                events: all[6..9].to_vec(),
            },
            0,
            &mut None,
        )
        .expect("durable journal 8..10");
    let first = show(&persisted, 8, None, None);
    assert_eq!(sequences(&first), (2..=9).collect::<Vec<_>>());
    let end = show(&persisted, 1, first.next_cursor, None);
    assert_eq!(sequences(&end), [10]);
    assert!(end.events[0].frame_id.is_none(), "journal identity is not a durable frame identity");
    let back = show(&persisted, 6, end.prev_cursor, None);
    assert_eq!(sequences(&back), (4..=9).collect::<Vec<_>>());
    assert!(back.events[4..].iter().all(|event| event.frame_id.is_none()));
    assert_eq!(back.incomplete_evidence, ["durable_tail_pending:8..10"]);
    assert_eq!(sequences(&show(&persisted, 1, back.next_cursor, None)), [10]);
    let head = show(&persisted, 6, back.prev_cursor, None);
    assert_eq!(sequences(&head), [2, 3]);
    assert!(head.prev_cursor.is_none());
}
