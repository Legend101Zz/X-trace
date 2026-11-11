//! Real SQLite/XTF composition for cumulative Health reports and viewer regressions.

#![allow(clippy::expect_used, clippy::unwrap_used, reason = "test fixture assertions")]

use std::sync::Arc;
use xtrace_application::ProjectRepository;
use xtrace_application::recording::{
    BeginRecording, EndpointObservationInput, FinishRecording, RecordingCaptureService,
    RecordingCompletion, RecordingPersistencePort, SegmentPolicy,
};
use xtrace_application::{
    ObservedEndpointReadPort, RecordingCompletionEvidence, RecordingReadPort, ShowWindowRequest,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    Project, ProjectId, RecordingId, RepositoryFingerprint, RuntimeSessionId, WallTime,
};
use xtrace_protocol::generated::agent::Health;
use xtrace_store::{OpenOptions, SqliteRecordingPersistence, SqliteRecordingReader, SqliteStore};

pub(crate) struct HealthFixture {
    pub(crate) root: tempfile::TempDir,
    pub(crate) store: SqliteStore,
    pub(crate) project_id: ProjectId,
    pub(crate) session_id: RuntimeSessionId,
    pub(crate) recording_id: RecordingId,
}

impl HealthFixture {
    pub(crate) fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let scratch = std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH").expect("private scratch");
        let root = tempfile::Builder::new()
            .prefix("health-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(scratch)
            .expect("private project directory");
        let database = root.path().join("metadata.sqlite3");
        let store = SqliteStore::open(&database, OpenOptions::default()).expect("store");
        std::fs::set_permissions(database, std::fs::Permissions::from_mode(0o600))
            .expect("private database");
        let project_id = ProjectId::new();
        store
            .project_repository()
            .insert_project(&Project {
                id: project_id,
                canonical_repo_hash: RepositoryFingerprint::from_canonical_path("/fixture/health"),
                display_name: "health fixture".into(),
                created_at: WallTime::now(),
                last_opened_at: WallTime::now(),
                config_schema_version: 1,
                effective_config_hash: String::new(),
                active_capture_policy_id: None,
                active_redaction_policy_id: None,
            })
            .expect("project");
        Self {
            root,
            store,
            project_id,
            session_id: RuntimeSessionId::new(),
            recording_id: RecordingId::new(),
        }
    }

    pub(crate) fn persistence(&self) -> SqliteRecordingPersistence {
        SqliteRecordingPersistence::new(self.store.clone(), self.root.path())
    }

    pub(crate) fn begin(&self) {
        self.persistence()
            .begin_recording(&BeginRecording {
                project_id: self.project_id,
                recording_id: self.recording_id,
                runtime_session_id: self.session_id,
                opened_at: WallTime::now(),
                endpoint_observation: EndpointObservationInput::default(),
                limitations: Vec::new(),
            })
            .expect("recording");
    }

    pub(crate) fn finish(&self, partial: bool) {
        // An empty stream still needs verified terminal evidence to be complete.
        let mut finish = FinishRecording::without_digest(self.recording_id, 1);
        if !partial {
            finish.event_digest = blake3::hash(&[]).as_bytes().to_vec();
        }
        assert_eq!(
            self.persistence().finish_recording(&finish).expect("finish recording"),
            if partial { RecordingCompletion::Partial } else { RecordingCompletion::Complete }
        );
    }
}

#[test]
fn session_context_tracks_latest_reports_only_for_recordings_of_that_session() {
    let fixture = HealthFixture::new();
    fixture.begin();
    fixture.finish(false);
    let same_session_recording = RecordingId::new();
    let other_session_recording = RecordingId::new();
    let other_session = RuntimeSessionId::new();
    let persistence = fixture.persistence();
    for (recording_id, runtime_session_id) in
        [(same_session_recording, fixture.session_id), (other_session_recording, other_session)]
    {
        persistence
            .begin_recording(&BeginRecording {
                project_id: fixture.project_id,
                recording_id,
                runtime_session_id,
                opened_at: WallTime::now(),
                endpoint_observation: EndpointObservationInput::default(),
                limitations: Vec::new(),
            })
            .expect("another recording");
    }
    persistence
        .record_session_rejections(fixture.project_id, other_session, 99)
        .expect("other session report");
    let reader = SqliteRecordingReader::new(fixture.store.clone(), fixture.root.path());
    for (report, expected) in
        [(None, None), (Some(0), Some("0")), (Some(7), Some("7")), (Some(3), Some("7"))]
    {
        if let Some(count) = report {
            persistence
                .record_session_rejections(fixture.project_id, fixture.session_id, count)
                .expect("session report after recording finished");
        }
        let (recordings, more) =
            reader.list_recordings(fixture.project_id, None, 10).expect("recording list");
        let (unmatched, unmatched_more) =
            reader.list_unmatched_recordings(fixture.project_id, None, 10).expect("unmatched list");
        assert!(!more);
        assert!(!unmatched_more);
        assert_eq!(recordings.len(), 3);
        assert_eq!(unmatched.len(), 3);
        for metadata in &recordings {
            let other = metadata.recording_id == other_session_recording;
            assert_eq!(
                metadata.session_context.runtime_session_id,
                if other { other_session } else { fixture.session_id }
            );
            assert_eq!(
                metadata.session_context.rejected_requests.as_deref(),
                if other { Some("99") } else { expected }
            );
            assert!(metadata.incomplete_evidence.is_empty());
            let observed = unmatched
                .iter()
                .find(|row| row.metadata.recording_id == metadata.recording_id)
                .expect("same recording in unmatched projection");
            assert_eq!(observed.metadata.session_context, metadata.session_context);
            assert!(observed.metadata.incomplete_evidence.is_empty());
            let window = reader
                .show_recording(&ShowWindowRequest {
                    project_id: fixture.project_id,
                    recording_id: metadata.recording_id,
                    limit: 10,
                    after_sequence: None,
                })
                .expect("recording window");
            assert_eq!(window.session_context, metadata.session_context);
            assert!(window.incomplete_evidence.is_empty());
            if metadata.recording_id == fixture.recording_id {
                assert_eq!(metadata.completion, RecordingCompletionEvidence::Complete);
                assert_eq!(window.completion, RecordingCompletionEvidence::Complete);
            }
        }
    }
}

#[tokio::test]
async fn health_rejections_are_durable_cumulative_and_isolated_before_any_recording() {
    let fixture = HealthFixture::new();
    let capture = Arc::new(RecordingCaptureService::new(
        Arc::new(fixture.persistence()),
        SegmentPolicy::default(),
        std::num::NonZeroUsize::new(16).expect("nonzero"),
    ));
    let pipeline = crate::recording_pipeline::RecordingPipeline::new(
        capture,
        EndpointObservationInput::default(),
    );
    let (_shutdown_tx, shutdown) = crate::daemon::shared_shutdown_channel();
    for status in ["", "ok", "recording-starts-rejected=1 private-canary"] {
        pipeline
            .process(
                crate::runtime::IncomingEnvelope::Health(Health {
                    status: status.to_owned(),
                    ..Health::default()
                }),
                fixture.project_id,
                fixture.session_id,
                shutdown.clone(),
            )
            .await
            .expect("unrecognized health status");
    }
    let connection = rusqlite::Connection::open_with_flags(
        fixture.root.path().join("metadata.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("independent reader");
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM session_health", [], |row| row.get::<_, i64>(0))
            .expect("unobserved counts"),
        0
    );
    drop(connection);
    for count in [7, 7, 3, 11] {
        pipeline
            .process(
                crate::runtime::IncomingEnvelope::Health(Health {
                    status: format!("recording-starts-rejected={count}"),
                    ..Health::default()
                }),
                fixture.project_id,
                fixture.session_id,
                shutdown.clone(),
            )
            .await
            .expect("persist Health");
    }
    let other_session = RuntimeSessionId::new();
    fixture
        .persistence()
        .record_session_rejections(fixture.project_id, other_session, 2)
        .expect("separate session");
    // A generic report must not clear the last observed count.
    pipeline
        .process(
            crate::runtime::IncomingEnvelope::Health(Health::default()),
            fixture.project_id,
            fixture.session_id,
            shutdown,
        )
        .await
        .expect("generic Health");
    drop(pipeline);
    let reopened = rusqlite::Connection::open_with_flags(
        fixture.root.path().join("metadata.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("independent durable reader");
    let count = |session: RuntimeSessionId| {
        reopened.query_row(
        "SELECT rejected_requests FROM session_health WHERE project_id = ?1 AND runtime_session_id = ?2",
        rusqlite::params![fixture.project_id.as_uuid().as_bytes(), session.as_uuid().as_bytes()],
        |row| row.get::<_, i64>(0),
    ).expect("stored count")
    };
    assert_eq!(count(fixture.session_id), 11);
    assert_eq!(count(other_session), 2);
    assert_eq!(
        reopened
            .query_row("SELECT COUNT(*) FROM recordings", [], |row| row.get::<_, i64>(0))
            .expect("recordings"),
        0
    );
    assert!(
        fixture
            .persistence()
            .record_session_rejections(ProjectId::new(), fixture.session_id, 1)
            .is_err()
    );
    assert!(
        fixture
            .persistence()
            .record_session_rejections(fixture.project_id, fixture.session_id, u64::MAX)
            .is_err()
    );
}

#[test]
fn rejection_status_is_exact_bounded_and_never_accepts_free_text() {
    for status in [
        "",
        "ok",
        "recording-starts-rejected=",
        "recording-starts-rejected=-1",
        "recording-starts-rejected=+1",
        "recording-starts-rejected=01",
        "recording-starts-rejected=1 private-canary",
        "recording-starts-rejected=9223372036854775808",
    ] {
        assert_eq!(crate::recording_pipeline::rejected_starts(status), None, "{status}");
    }
    assert_eq!(crate::recording_pipeline::rejected_starts("recording-starts-rejected=0"), Some(0));
    assert_eq!(
        crate::recording_pipeline::rejected_starts("recording-starts-rejected=9223372036854775807"),
        Some(i64::MAX as u64)
    );
}
