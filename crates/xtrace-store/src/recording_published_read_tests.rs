#[cfg(unix)]
mod published_reads {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Copy, Debug)]
    enum ReadKind {
        List,
        Show,
        Unmatched,
    }

    fn assert_prefix(
        view: &SqliteRecordingStore<'_>,
        project: ProjectId,
        recording: RecordingId,
        kind: ReadKind,
        sealed: u64,
        last: u64,
        pending: Option<&str>,
    ) {
        let expected = pending.map(str::to_owned).into_iter().collect::<Vec<_>>();
        match kind {
            ReadKind::Show => {
                let page = view
                    .read_recording_window(
                        &ShowWindowRequest {
                            project_id: project,
                            recording_id: recording,
                            limit: 10,
                            after_sequence: None,
                        },
                        None,
                    )
                    .expect("concurrent show succeeds");
                assert_eq!(page.status, RecordingStatus::Recording);
                assert_eq!(page.completion, RecordingCompletionEvidence::Unavailable);
                assert_eq!(page.segment_count, sealed.to_string());
                assert_eq!(
                    page.events.iter().map(|event| event.sequence.clone()).collect::<Vec<_>>(),
                    (2..=last).map(|sequence| sequence.to_string()).collect::<Vec<_>>()
                );
                assert_eq!(page.incomplete_evidence, expected);
            }
            ReadKind::List | ReadKind::Unmatched => {
                let rows = if matches!(kind, ReadKind::List) {
                    view.list_recording_metadata(project, None, 10).expect("concurrent list").0
                } else {
                    view.list_unmatched_recordings(project, None, 10)
                        .expect("concurrent endpoint list")
                        .0
                        .into_iter()
                        .map(|row| row.metadata)
                        .collect()
                };
                assert_eq!(rows.len(), 1);
                let row = &rows[0];
                assert_eq!(row.status, RecordingStatus::Recording);
                assert_eq!(row.completion, RecordingCompletionEvidence::Unavailable);
                assert_eq!(row.segment_count, sealed.to_string());
                assert_eq!(row.event_count, last.saturating_sub(1).to_string());
                assert_eq!(row.first_sequence.as_deref(), (last >= 2).then_some("2"));
                assert_eq!(row.last_sequence, (last >= 2).then(|| last.to_string()));
                assert_eq!(row.incomplete_evidence, expected);
            }
        }
    }

    #[test]
    fn list_and_show_interleave_with_each_durable_publication_step() {
        for (phase, sealed, last, pending) in [
            ("journal-checkpoint-before-sync", 0, 3, Some("durable_tail_pending:2..3")),
            ("journal-before-sync", 0, 3, Some("durable_tail_pending:2..3")),
            ("journal-checkpoint-before-rename", 0, 3, Some("durable_tail_pending:2..3")),
            ("journal-after-sync", 0, 4, Some("durable_tail_pending:2..4")),
            ("after-object-directory-sync", 0, 3, Some("durable_tail_pending:2..3")),
            ("before-transaction-commit", 0, 3, Some("durable_tail_pending:2..3")),
            ("after-commit-before-cleanup", 1, 4, None),
        ] {
            let fixture = on_disk_store("published-step");
            let project = ProjectId::new();
            insert_project(&fixture.store, project);
            let anchor = request(project, RecordingId::new(), RuntimeSessionId::new(), opened_at());
            let view = fixture.store.recording_store(&fixture.root).expect("writer view");
            view.begin_recording(&anchor).expect("begin");
            let mut checkpoint = None;
            view.journal_tail(
                &journal_request(project, anchor.recording_id, &[2, 3]),
                0,
                &mut checkpoint,
            )
            .expect("published prefix");
            let reader = SqliteStore::open(
                &fixture.database,
                OpenOptions::default().with_must_exist(true).with_read_only(true),
            )
            .expect("independent read-only WAL connection");
            let root = fixture.root.clone();
            let recording = anchor.recording_id;
            let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let hook_observed = observed.clone();
            COMMIT_OBSERVER.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |point| {
                    if point != phase {
                        return;
                    }
                    std::thread::scope(|scope| {
                        scope
                            .spawn(|| {
                                let view = reader.recording_store(&root).expect("reader view");
                                for kind in [ReadKind::List, ReadKind::Show, ReadKind::Unmatched] {
                                    assert_prefix(
                                        &view, project, recording, kind, sealed, last, pending,
                                    );
                                }
                            })
                            .join()
                            .expect("reader finishes while writer is paused");
                    });
                    hook_observed.store(true, Ordering::SeqCst);
                }));
            });
            let result = if phase.starts_with("journal-") {
                view.journal_tail(&journal_request(project, recording, &[4]), 2, &mut checkpoint)
            } else {
                view.commit_segment(&segment_request(project, recording, 0, &[2, 3, 4])).map(|_| ())
            };
            COMMIT_OBSERVER.with(|hook| hook.borrow_mut().take());
            result.expect("writer completes");
            assert!(observed.load(Ordering::SeqCst), "must observe {phase}");
        }
    }

    #[test]
    fn a_pinned_list_or_show_prevents_cleanup_and_the_next_journal_from_overtaking_sqlite() {
        for kind in [ReadKind::List, ReadKind::Show, ReadKind::Unmatched] {
            let fixture = on_disk_store("published-seal");
            let project = ProjectId::new();
            insert_project(&fixture.store, project);
            let anchor = request(project, RecordingId::new(), RuntimeSessionId::new(), opened_at());
            let recording = anchor.recording_id;
            let view = fixture.store.recording_store(&fixture.root).expect("view");
            view.begin_recording(&anchor).expect("begin");
            view.journal_tail(&journal_request(project, recording, &[2, 3]), 0, &mut None)
                .expect("published prefix");
            let reader_store = SqliteStore::open(
                &fixture.database,
                OpenOptions::default().with_must_exist(true).with_read_only(true),
            )
            .expect("independent reader");
            let (paused_tx, paused_rx) = std::sync::mpsc::channel();
            let (resume_tx, resume_rx) = std::sync::mpsc::channel();
            let (cleanup_tx, cleanup_rx) = std::sync::mpsc::channel();
            std::thread::scope(|scope| {
                let reader_root = &fixture.root;
                let reader = scope.spawn(move || {
                    AFTER_READ_SNAPSHOT.with(|hook| {
                        *hook.borrow_mut() = Some(Box::new(move || {
                            paused_tx.send(()).expect("SQLite snapshot pinned");
                            resume_rx.recv().expect("resume read");
                        }));
                    });
                    let view = reader_store.recording_store(reader_root).expect("reader view");
                    assert_prefix(
                        &view,
                        project,
                        recording,
                        kind,
                        0,
                        3,
                        Some("durable_tail_pending:2..3"),
                    );
                    AFTER_READ_SNAPSHOT.with(|hook| hook.borrow_mut().take());
                });
                paused_rx.recv().expect("reader paused before journal read");
                let writer = scope.spawn(|| {
                    view.commit_segment(&segment_request(project, recording, 0, &[2, 3, 4]))
                        .expect("seal can commit during a read");
                    let root = fixture.root.join("journals");
                    recording_journal::BEFORE_CLEANUP.with(|hook| {
                        *hook.borrow_mut() = Some(Box::new(move || {
                            use rustix::fs::{FlockOperation, flock};
                            let directory =
                                xtrace_private_storage::open_private_directory_descriptor(&root)
                                    .expect("journals descriptor");
                            let blocked =
                                flock(&directory, FlockOperation::NonBlockingLockExclusive)
                                    == Err(rustix::io::Errno::WOULDBLOCK);
                            cleanup_tx.send(blocked).expect("observed publication guard");
                        }));
                    });
                    view.clear_segment_journal(recording, 0).expect("cleanup after reader");
                    recording_journal::BEFORE_CLEANUP.with(|hook| hook.borrow_mut().take());
                    let mut next = journal_request(project, recording, &[5]);
                    next.segment_ordinal = 1;
                    view.journal_tail(&next, 0, &mut None).expect("next durable tail");
                });
                let blocked = cleanup_rx.recv().expect("writer reached cleanup");
                resume_tx.send(()).expect("reader can complete");
                reader.join().expect("consistent old prefix");
                writer.join().expect("writer completes");
                assert!(blocked, "cleanup must wait for {kind:?}'s SQLite/journal snapshot");
            });
            assert_prefix(&view, project, recording, kind, 1, 5, Some("durable_tail_pending:5..5"));
        }
    }

    #[test]
    fn show_keeps_status_and_terminal_proof_on_the_same_sqlite_snapshot() {
        for navigation in [false, true] {
            let fixture = on_disk_store("published-finish");
            let project = ProjectId::new();
            insert_project(&fixture.store, project);
            let anchor = request(project, RecordingId::new(), RuntimeSessionId::new(), opened_at());
            let view = fixture.store.recording_store(&fixture.root).expect("view");
            view.begin_recording(&anchor).expect("begin");
            let writer =
                SqliteStore::open(&fixture.database, OpenOptions::default()).expect("writer");
            let root = fixture.root.clone();
            let recording = anchor.recording_id;
            let frame_id = if navigation {
                let mut segment = segment_request(project, recording, 0, &[2]);
                segment.events[0].event.as_mut().expect("event").kind =
                    xtrace_protocol::generated::agent::RecordingEventKind::FrameEnter as i32;
                view.commit_segment(&segment).expect("indexed frame");
                let page = view
                    .read_recording_window(
                        &ShowWindowRequest {
                            project_id: project,
                            recording_id: recording,
                            limit: 10,
                            after_sequence: None,
                        },
                        None,
                    )
                    .expect("frame identity");
                Some(page.events[0].frame_id.expect("indexed frame id"))
            } else {
                None
            };
            AFTER_READ_SNAPSHOT.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    let writer = writer.recording_store(&root).expect("writer view");
                    writer
                        .finish_recording(&FinishRecording::without_digest(
                            recording,
                            if navigation { 2 } else { 1 },
                        ))
                        .expect("concurrent partial Finish");
                }));
            });
            if let Some(frame_id) = frame_id {
                let frame = view
                    .read_frame_navigation(project, recording, frame_id)
                    .expect("around-frame anchor tolerates concurrent Finish");
                assert_eq!(frame.frame_id, frame_id);
            } else {
                assert_prefix(&view, project, recording, ReadKind::Show, 0, 1, None);
            }
            AFTER_READ_SNAPSHOT.with(|hook| hook.borrow_mut().take());
            let page = view
                .read_recording_window(
                    &ShowWindowRequest {
                        project_id: project,
                        recording_id: recording,
                        limit: 10,
                        after_sequence: None,
                    },
                    None,
                )
                .expect("next snapshot observes Finish");
            assert_eq!(page.status, RecordingStatus::Partial);
            assert_eq!(page.completion, RecordingCompletionEvidence::Partial);
            assert_eq!(page.incomplete_evidence, ["persisted_status:partial"]);
        }
    }

    #[test]
    fn missing_acknowledged_tail_and_oversized_journal_files_are_corruption() {
        for corruption in ["missing-tail", "oversized-checkpoint", "oversized-tail"] {
            let fixture = on_disk_store("published-corruption");
            let project = ProjectId::new();
            insert_project(&fixture.store, project);
            let anchor = request(project, RecordingId::new(), RuntimeSessionId::new(), opened_at());
            let view = fixture.store.recording_store(&fixture.root).expect("view");
            view.begin_recording(&anchor).expect("begin");
            view.journal_tail(
                &journal_request(project, anchor.recording_id, &[2, 3]),
                0,
                &mut None,
            )
            .expect("acknowledged prefix");
            if corruption == "missing-tail" {
                std::fs::remove_file(
                    fixture.root.join("journals").join(format!("{}.tail", anchor.recording_id)),
                )
                .expect("remove acknowledged tail");
            } else if corruption == "oversized-checkpoint" {
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(
                        fixture
                            .root
                            .join("journals")
                            .join(format!("{}.tail.commit", anchor.recording_id)),
                    )
                    .expect("checkpoint")
                    .write_all(&[0])
                    .expect("corrupt size");
            } else {
                use xtrace_application::recording::{
                    DEFAULT_SEGMENT_EVENT_BYTES, DEFAULT_SEGMENT_EVENTS,
                };
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(
                        fixture.root.join("journals").join(format!("{}.tail", anchor.recording_id)),
                    )
                    .expect("tail")
                    .set_len(
                        (DEFAULT_SEGMENT_EVENT_BYTES + DEFAULT_SEGMENT_EVENTS * 32 + 1024) as u64,
                    )
                    .expect("oversized journal");
            }
            let error =
                view.list_recording_metadata(project, None, 10).expect_err("corruption is visible");
            assert_eq!(error.kind(), RecordingStoreErrorKind::Corruption);
            assert_eq!(error.code(), "XTR-STORE-OBJECT-CORRUPT");
            let error = view
                .read_recording_window(
                    &ShowWindowRequest {
                        project_id: project,
                        recording_id: anchor.recording_id,
                        limit: 10,
                        after_sequence: None,
                    },
                    None,
                )
                .expect_err("show reports corruption too");
            assert_eq!(error.kind(), RecordingStoreErrorKind::Corruption);
        }
    }
}
