//! Application recording-persistence port backed by the SQLite/XTF store.

use std::path::PathBuf;

use prost::Message as _;
use xtrace_application::recording::{
    AcceptedRecordingEvent, BeginRecording, BeginRecordingDisposition as PortBeginDisposition,
    BeginRecordingReceipt as PortBeginReceipt, PersistRecordingSegment,
    PersistSegmentDisposition as PortSegmentDisposition,
    PersistSegmentReceipt as PortSegmentReceipt, RecordingPersistencePort,
};
use xtrace_application::{PortError, PortErrorKind};
use xtrace_domain::CorrelationId;
use xtrace_protocol::xtf::XtfEventEnvelope;

use crate::SqliteStore;
use crate::recording_store::{
    BeginRecordingDisposition, BeginRecordingRequest, RecordingStoreError, RecordingStoreErrorKind,
    SegmentCommitDisposition, SegmentCommitRequest,
};

/// SQLite implementation of the application recording-persistence port.
///
/// The project data root is explicit so recording objects are bound to the same
/// per-project directory as `metadata.sqlite3`, rather than to a repository.
/// The store is owned by this adapter; short-lived root-bound views are created
/// for each synchronous operation.
#[derive(Clone, Debug)]
pub struct SqliteRecordingPersistence {
    store: SqliteStore,
    project_data_root: PathBuf,
}

impl SqliteRecordingPersistence {
    /// Creates an adapter bound to one project data directory.
    #[must_use]
    pub fn new(store: SqliteStore, project_data_root: impl Into<PathBuf>) -> Self {
        Self { store, project_data_root: project_data_root.into() }
    }
}

impl RecordingPersistencePort for SqliteRecordingPersistence {
    type Event = XtfEventEnvelope;

    fn validate_event(&self, event: &AcceptedRecordingEvent<Self::Event>) -> Result<(), PortError> {
        validate_xtf_event(event).map(|_| ())
    }

    fn begin_recording(&self, request: &BeginRecording) -> Result<PortBeginReceipt, PortError> {
        let view =
            self.store.recording_store(&self.project_data_root).map_err(map_recording_error)?;
        let receipt = view
            .begin_recording(&BeginRecordingRequest {
                project_id: request.project_id,
                recording_id: request.recording_id,
                runtime_session_id: request.runtime_session_id,
                opened_at: request.opened_at,
            })
            .map_err(map_recording_error)?;
        let disposition = match receipt.disposition {
            BeginRecordingDisposition::Inserted => PortBeginDisposition::Inserted,
            BeginRecordingDisposition::ExactReplay => PortBeginDisposition::ExactReplay,
        };
        Ok(PortBeginReceipt { recording_id: receipt.recording_id, disposition })
    }

    fn persist_segment(
        &self,
        request: &PersistRecordingSegment<Self::Event>,
    ) -> Result<PortSegmentReceipt, PortError> {
        let events =
            request.events.iter().map(validate_xtf_event).collect::<Result<Vec<_>, _>>()?;
        let view =
            self.store.recording_store(&self.project_data_root).map_err(map_recording_error)?;
        let receipt = view
            .commit_segment(&SegmentCommitRequest {
                project_id: request.project_id,
                recording_id: request.recording_id,
                segment_ordinal: request.segment_ordinal,
                events,
            })
            .map_err(map_recording_error)?;
        let disposition = match receipt.disposition {
            SegmentCommitDisposition::Inserted => PortSegmentDisposition::Inserted,
            SegmentCommitDisposition::ExactReplay => PortSegmentDisposition::ExactReplay,
        };
        Ok(PortSegmentReceipt {
            recording_id: receipt.recording_id,
            segment_ordinal: receipt.segment_ordinal,
            disposition,
        })
    }
}

fn validate_xtf_event(
    event: &AcceptedRecordingEvent<XtfEventEnvelope>,
) -> Result<XtfEventEnvelope, PortError> {
    let Some(payload) = event.payload.event.as_ref() else {
        return Err(PortError::new(
            PortErrorKind::Validation,
            "recording event envelope is missing its typed payload",
            CorrelationId::new(),
        ));
    };
    if event.recording_seq != event.payload.recording_seq
        || event.recording_seq != payload.recording_seq
        || event.monotonic_ns != payload.monotonic_ns
    {
        return Err(PortError::new(
            PortErrorKind::Validation,
            "recording event metadata disagrees with its XTF envelope or typed payload",
            CorrelationId::new(),
        ));
    }
    if event.payload.encode_to_vec() != event.canonical_bytes {
        return Err(PortError::new(
            PortErrorKind::Validation,
            "recording event canonical bytes do not match its XTF envelope",
            CorrelationId::new(),
        ));
    }
    Ok(event.payload.clone())
}

fn map_recording_error(error: RecordingStoreError) -> PortError {
    let kind = match error.kind() {
        RecordingStoreErrorKind::Validation | RecordingStoreErrorKind::Permission => {
            PortErrorKind::Validation
        }
        RecordingStoreErrorKind::NotFound => PortErrorKind::NotFound,
        RecordingStoreErrorKind::Conflict => PortErrorKind::Conflict,
        RecordingStoreErrorKind::Corruption => PortErrorKind::Corruption,
        RecordingStoreErrorKind::Transport => PortErrorKind::Transport,
        RecordingStoreErrorKind::Compatibility => PortErrorKind::Compatibility,
        RecordingStoreErrorKind::Busy | RecordingStoreErrorKind::Resource => {
            PortErrorKind::Resource
        }
        RecordingStoreErrorKind::Internal => PortErrorKind::Internal,
    };
    let mut mapped = PortError::new(
        kind,
        format!("{}: {}", error.code(), error.message()),
        error.correlation_id(),
    );
    if let Some(source) = error.source() {
        mapped = mapped.with_source(source);
    }
    mapped
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "tests assert on fixture setup")]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    use prost::Message as _;
    use xtrace_application::PortErrorKind;
    use xtrace_application::ProjectRepository;
    use xtrace_application::recording::{
        AcceptedRecordingEvent, BeginRecording, FinishRecording, PersistRecordingSegment,
        RecordEvents, RecordingCapture, RecordingCaptureService, RecordingPersistencePort,
        SegmentPolicy,
    };
    use xtrace_domain::{
        Project, ProjectId, RecordingId, RepositoryFingerprint, RuntimeSessionId, WallTime,
    };
    use xtrace_protocol::generated::agent::RecordingEvent;
    use xtrace_protocol::xtf::XtfEventEnvelope;

    use crate::{OpenOptions, SqliteRecordingPersistence, SqliteStore};

    fn fixture() -> (tempfile::TempDir, SqliteStore, Project) {
        let temp_base = std::env::temp_dir().canonicalize().expect("canonical temp base");
        let directory = tempfile::Builder::new()
            .prefix("recording-port-")
            .tempdir_in(temp_base)
            .expect("project directory");
        let root = directory.path();
        #[cfg(unix)]
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
            .expect("secure project directory");
        let store = SqliteStore::open(&root.join("metadata.sqlite3"), OpenOptions::default())
            .expect("open SQLite store");
        #[cfg(unix)]
        std::fs::set_permissions(
            root.join("metadata.sqlite3"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("secure database file");
        let timestamp = WallTime::from_parts(2026, 9, 29, 1, 2, 3, 0).expect("timestamp");
        let project = Project {
            id: ProjectId::new(),
            canonical_repo_hash: RepositoryFingerprint::from_canonical_path("/fixture/repo"),
            display_name: "fixture".to_owned(),
            created_at: timestamp,
            last_opened_at: timestamp,
            config_schema_version: 1,
            effective_config_hash: String::new(),
            active_capture_policy_id: None,
            active_redaction_policy_id: None,
        };
        store.project_repository().insert_project(&project).expect("insert project");
        (directory, store, project)
    }

    fn begin(project_id: ProjectId, recording_id: RecordingId) -> BeginRecording {
        BeginRecording {
            project_id,
            recording_id,
            runtime_session_id: RuntimeSessionId::new(),
            opened_at: WallTime::from_parts(2026, 9, 29, 1, 2, 3, 0).expect("timestamp"),
        }
    }

    fn event(sequence: u64, event_id: &str) -> AcceptedRecordingEvent<XtfEventEnvelope> {
        let nested = RecordingEvent {
            event_id: event_id.to_owned(),
            recording_seq: sequence,
            monotonic_ns: sequence * 10,
            ..RecordingEvent::default()
        };
        let payload = XtfEventEnvelope { recording_seq: sequence, event: Some(nested) };
        let canonical_bytes = payload.encode_to_vec();
        AcceptedRecordingEvent {
            recording_seq: sequence,
            monotonic_ns: sequence * 10,
            canonical_bytes,
            payload,
        }
    }

    #[test]
    fn sqlite_adapter_replays_begin_and_segment_idempotently() {
        let (directory, store, project) = fixture();
        let adapter = SqliteRecordingPersistence::new(store, directory.path());
        let request = begin(project.id(), RecordingId::new());
        assert_eq!(
            adapter.begin_recording(&request).expect("begin").disposition,
            xtrace_application::recording::BeginRecordingDisposition::Inserted
        );
        assert_eq!(
            adapter.begin_recording(&request).expect("begin replay").disposition,
            xtrace_application::recording::BeginRecordingDisposition::ExactReplay
        );
        let segment = PersistRecordingSegment {
            project_id: project.id(),
            recording_id: request.recording_id,
            segment_ordinal: 0,
            events: vec![event(2, "event-2")],
        };
        assert_eq!(
            adapter.persist_segment(&segment).expect("persist segment").disposition,
            xtrace_application::recording::PersistSegmentDisposition::Inserted
        );
        assert_eq!(
            adapter.persist_segment(&segment).expect("segment replay").disposition,
            xtrace_application::recording::PersistSegmentDisposition::ExactReplay
        );
        let changed =
            PersistRecordingSegment { events: vec![event(2, "changed-event")], ..segment };
        let error = adapter.persist_segment(&changed).expect_err("changed replay");
        assert_eq!(error.kind(), PortErrorKind::Conflict);
        assert!(error.message().contains("XTR-STORE-SEGMENT-CONFLICT"));
        assert!(error.source().is_none() || !error.source().unwrap().contains("/"));
    }

    #[test]
    fn capture_preflights_the_complete_batch_before_accepting_or_persisting_events() {
        let (directory, store, project) = fixture();
        let adapter = std::sync::Arc::new(SqliteRecordingPersistence::new(store, directory.path()));
        let capture = RecordingCaptureService::new(
            std::sync::Arc::clone(&adapter),
            SegmentPolicy::default(),
            std::num::NonZeroUsize::new(2).expect("non-zero recording limit"),
        );
        let begin = begin(project.id(), RecordingId::new());
        capture.begin_recording(begin).expect("begin");

        let first_attempt = event(2, "first-attempt");
        let mut malformed_later = event(3, "malformed-later");
        malformed_later.payload.event.as_mut().expect("nested event").monotonic_ns += 1;
        malformed_later.canonical_bytes = malformed_later.payload.encode_to_vec();
        let error = capture
            .record_events(RecordEvents {
                recording_id: begin.recording_id,
                events: vec![first_attempt, malformed_later],
            })
            .expect_err("malformed later event rejects the whole batch");
        assert_eq!(error.kind(), PortErrorKind::Validation);

        let corrected_first = event(2, "corrected-first");
        let corrected_later = event(3, "corrected-later");
        let retry = capture
            .record_events(RecordEvents {
                recording_id: begin.recording_id,
                events: vec![corrected_first.clone(), corrected_later.clone()],
            })
            .expect("corrected events at the same sequences remain admissible");
        assert_eq!(retry.accepted, 2);
        let finished = capture
            .finish_recording(FinishRecording {
                recording_id: begin.recording_id,
                final_recording_seq: 3,
            })
            .expect("finish persists the corrected segment");
        assert_eq!(finished.persisted_segments, 1);

        let durable_replay = adapter
            .persist_segment(&PersistRecordingSegment {
                project_id: project.id(),
                recording_id: begin.recording_id,
                segment_ordinal: 0,
                events: vec![corrected_first, corrected_later],
            })
            .expect("segment is durable in SQLite");
        assert_eq!(
            durable_replay.disposition,
            xtrace_application::recording::PersistSegmentDisposition::ExactReplay
        );
    }

    #[test]
    fn capture_validates_typed_payload_on_exact_canonical_duplicate_replay() {
        let (directory, store, project) = fixture();
        let adapter = std::sync::Arc::new(SqliteRecordingPersistence::new(store, directory.path()));
        let capture = RecordingCaptureService::new(
            std::sync::Arc::clone(&adapter),
            SegmentPolicy::default(),
            std::num::NonZeroUsize::new(2).expect("non-zero recording limit"),
        );
        let begin = begin(project.id(), RecordingId::new());
        capture.begin_recording(begin).expect("begin");

        let original = event(2, "event-2");
        capture
            .record_events(RecordEvents {
                recording_id: begin.recording_id,
                events: vec![original.clone()],
            })
            .expect("accept original");

        let mut malformed_duplicate = original.clone();
        malformed_duplicate.payload.event.as_mut().expect("nested event").recording_seq = 3;
        let error = capture
            .record_events(RecordEvents {
                recording_id: begin.recording_id,
                events: vec![malformed_duplicate],
            })
            .expect_err("malformed typed payload cannot hide behind duplicate bytes");
        assert_eq!(error.kind(), PortErrorKind::Validation);

        let correct_duplicate = capture
            .record_events(RecordEvents {
                recording_id: begin.recording_id,
                events: vec![original.clone()],
            })
            .expect("original duplicate remains accepted");
        assert_eq!(correct_duplicate.duplicates, 1);
        assert_eq!(correct_duplicate.accepted, 0);
        assert_eq!(correct_duplicate.persisted_segments, 0);

        let finished = capture
            .finish_recording(FinishRecording {
                recording_id: begin.recording_id,
                final_recording_seq: 2,
            })
            .expect("finish persists the original event");
        assert_eq!(finished.persisted_segments, 1);
        let durable_replay = adapter
            .persist_segment(&PersistRecordingSegment {
                project_id: project.id(),
                recording_id: begin.recording_id,
                segment_ordinal: 0,
                events: vec![original],
            })
            .expect("stored segment remains the original");
        assert_eq!(
            durable_replay.disposition,
            xtrace_application::recording::PersistSegmentDisposition::ExactReplay
        );
    }

    #[test]
    fn sqlite_adapter_maps_root_and_missing_recording_errors_safely() {
        let (directory, store, project) = fixture();
        let wrong_root = directory.path().join("wrong-root");
        std::fs::create_dir(&wrong_root).expect("wrong root");
        let adapter = SqliteRecordingPersistence::new(store.clone(), &wrong_root);
        let error = adapter
            .begin_recording(&begin(project.id(), RecordingId::new()))
            .expect_err("root mismatch");
        assert_eq!(error.kind(), PortErrorKind::Validation);
        assert!(!error.correlation_id().to_string().is_empty());

        let absent_root = directory.path().join("absent-root");
        let adapter = SqliteRecordingPersistence::new(store.clone(), absent_root);
        let error = adapter
            .begin_recording(&begin(project.id(), RecordingId::new()))
            .expect_err("absent root");
        assert_eq!(error.kind(), PortErrorKind::Transport);
        assert_eq!(error.source(), Some("filesystem metadata failure"));
        assert!(!error.message().contains(directory.path().to_string_lossy().as_ref()));

        let adapter = SqliteRecordingPersistence::new(store, directory.path());
        let error = adapter
            .begin_recording(&begin(ProjectId::new(), RecordingId::new()))
            .expect_err("missing project");
        assert_eq!(error.kind(), PortErrorKind::NotFound);
        assert!(error.message().contains("XTR-STORE-RECORDING"));
    }

    #[test]
    fn sqlite_adapter_rejects_canonical_byte_disagreement_before_store_write() {
        let (directory, store, project) = fixture();
        let adapter = SqliteRecordingPersistence::new(store, directory.path());
        let begin = begin(project.id(), RecordingId::new());
        adapter.begin_recording(&begin).expect("begin");

        let mut outer_mismatch = event(2, "event-2");
        outer_mismatch.recording_seq = 3;
        let error = adapter
            .persist_segment(&PersistRecordingSegment {
                project_id: project.id(),
                recording_id: begin.recording_id,
                segment_ordinal: 0,
                events: vec![outer_mismatch],
            })
            .expect_err("outer/envelope mismatch");
        assert_eq!(error.kind(), PortErrorKind::Validation);

        let mut nested_mismatch = event(2, "event-2");
        nested_mismatch.payload.event.as_mut().expect("nested event").recording_seq = 3;
        nested_mismatch.canonical_bytes = nested_mismatch.payload.encode_to_vec();
        let error = adapter
            .persist_segment(&PersistRecordingSegment {
                project_id: project.id(),
                recording_id: begin.recording_id,
                segment_ordinal: 0,
                events: vec![nested_mismatch],
            })
            .expect_err("envelope/nested mismatch");
        assert_eq!(error.kind(), PortErrorKind::Validation);

        let mut invalid = event(2, "event-2");
        invalid.canonical_bytes.push(0);
        let error = adapter
            .persist_segment(&PersistRecordingSegment {
                project_id: project.id(),
                recording_id: begin.recording_id,
                segment_ordinal: 0,
                events: vec![invalid],
            })
            .expect_err("canonical mismatch");
        assert_eq!(error.kind(), PortErrorKind::Validation);

        let persisted = adapter
            .persist_segment(&PersistRecordingSegment {
                project_id: project.id(),
                recording_id: begin.recording_id,
                segment_ordinal: 0,
                events: vec![event(2, "event-2")],
            })
            .expect("valid request proves prior rejections did not write");
        assert_eq!(
            persisted.disposition,
            xtrace_application::recording::PersistSegmentDisposition::Inserted
        );
    }
}
