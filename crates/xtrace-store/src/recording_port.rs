//! Application recording-persistence port backed by the SQLite/XTF store.

use std::path::PathBuf;

use prost::Message as _;
use xtrace_application::observed_endpoint_queries::{
    ObservedEndpointKey, ObservedEndpointReadPort, ObservedEndpointRecord, ObservedRecordingKey,
    ObservedRecordingRecord,
};
use xtrace_application::recording::{
    AcceptedRecordingEvent, BeginRecording, BeginRecordingDisposition as PortBeginDisposition,
    BeginRecordingReceipt as PortBeginReceipt, FinishRecording, PersistRecordingSegment,
    PersistSegmentDisposition as PortSegmentDisposition,
    PersistSegmentReceipt as PortSegmentReceipt, RecordingCompletion, RecordingPersistencePort,
};
use xtrace_application::recording_queries::{
    RecordingEventWindow, RecordingMetadata, RecordingReadPort, ShowWindowRequest,
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

/// SQLite/XTF implementation of the framework-neutral recording read port.
///
/// Each operation creates a root-bound store view, so object lookup and
/// verification use the same selected project data root as the SQLite file.
#[derive(Clone, Debug)]
pub struct SqliteRecordingReader {
    store: SqliteStore,
    project_data_root: PathBuf,
    source_root: Option<PathBuf>,
}

impl SqliteRecordingReader {
    /// Creates a read adapter bound to one project data directory.
    #[must_use]
    pub fn new(store: SqliteStore, project_data_root: impl Into<PathBuf>) -> Self {
        Self { store, project_data_root: project_data_root.into(), source_root: None }
    }

    /// Enables bounded read-time source verification against a canonical repository root.
    #[must_use]
    pub fn with_source_root(mut self, source_root: impl Into<PathBuf>) -> Self {
        self.source_root = Some(source_root.into());
        self
    }
}

impl RecordingReadPort for SqliteRecordingReader {
    fn frame_navigation(
        &self,
        project_id: xtrace_domain::ProjectId,
        recording_id: xtrace_domain::RecordingId,
        frame_id: xtrace_domain::FrameId,
    ) -> Result<xtrace_application::FrameNavigationView, PortError> {
        let view =
            self.store.recording_store(&self.project_data_root).map_err(map_recording_error)?;
        view.read_frame_navigation(project_id, recording_id, frame_id).map_err(map_recording_error)
    }

    fn list_recordings(
        &self,
        project_id: xtrace_domain::ProjectId,
        after: Option<xtrace_domain::RecordingId>,
        limit: u32,
    ) -> Result<(Vec<RecordingMetadata>, bool), PortError> {
        let view =
            self.store.recording_store(&self.project_data_root).map_err(map_recording_error)?;
        view.list_recording_metadata(project_id, after, limit).map_err(map_recording_error)
    }

    fn show_recording(
        &self,
        request: &ShowWindowRequest,
    ) -> Result<RecordingEventWindow, PortError> {
        let view =
            self.store.recording_store(&self.project_data_root).map_err(map_recording_error)?;
        view.read_recording_window(request, self.source_root.as_deref())
            .map_err(map_recording_error)
    }
}

impl ObservedEndpointReadPort for SqliteRecordingReader {
    fn list_observed_endpoints(
        &self,
        project_id: xtrace_domain::ProjectId,
        after: Option<&ObservedEndpointKey>,
        limit: u32,
    ) -> Result<(Vec<ObservedEndpointRecord>, bool), PortError> {
        let view =
            self.store.recording_store(&self.project_data_root).map_err(map_recording_error)?;
        view.list_observed_endpoints(project_id, after, limit).map_err(map_recording_error)
    }

    fn list_operation_recordings(
        &self,
        project_id: xtrace_domain::ProjectId,
        operation_id: xtrace_domain::OperationId,
        after: Option<&ObservedRecordingKey>,
        limit: u32,
    ) -> Result<(Vec<ObservedRecordingRecord>, bool), PortError> {
        let view =
            self.store.recording_store(&self.project_data_root).map_err(map_recording_error)?;
        view.list_operation_recordings(project_id, operation_id, after, limit)
            .map_err(map_recording_error)
    }

    fn list_unmatched_recordings(
        &self,
        project_id: xtrace_domain::ProjectId,
        after: Option<&ObservedRecordingKey>,
        limit: u32,
    ) -> Result<(Vec<ObservedRecordingRecord>, bool), PortError> {
        let view =
            self.store.recording_store(&self.project_data_root).map_err(map_recording_error)?;
        view.list_unmatched_recordings(project_id, after, limit).map_err(map_recording_error)
    }
}

impl RecordingPersistencePort for SqliteRecordingPersistence {
    type Event = XtfEventEnvelope;

    fn validate_event(&self, event: &AcceptedRecordingEvent<Self::Event>) -> Result<(), PortError> {
        validate_xtf_event(event).map(|_| ())
    }

    fn begin_recording(&self, request: &BeginRecording) -> Result<PortBeginReceipt, PortError> {
        // One admission scope per store call (ADR 0008 Amendment 1); never held across calls.
        let _scope = xtrace_private_storage::AdmissionScope::enter();
        let view =
            self.store.recording_store(&self.project_data_root).map_err(map_recording_error)?;
        let receipt = view
            .begin_recording(&BeginRecordingRequest {
                project_id: request.project_id,
                recording_id: request.recording_id,
                runtime_session_id: request.runtime_session_id,
                opened_at: request.opened_at,
                endpoint_observation: request.endpoint_observation.clone(),
            })
            .map_err(map_recording_error)?;
        let disposition = match receipt.disposition {
            BeginRecordingDisposition::Inserted => PortBeginDisposition::Inserted,
            BeginRecordingDisposition::ExactReplay => PortBeginDisposition::ExactReplay,
            BeginRecordingDisposition::LegacyObservationAbsent => {
                PortBeginDisposition::LegacyObservationAbsent
            }
        };
        Ok(PortBeginReceipt { recording_id: receipt.recording_id, disposition })
    }

    fn persist_segment(
        &self,
        request: &PersistRecordingSegment<Self::Event>,
    ) -> Result<PortSegmentReceipt, PortError> {
        // One admission scope per store call (ADR 0008 Amendment 1); never held across calls.
        let _scope = xtrace_private_storage::AdmissionScope::enter();
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

    fn finish_recording(
        &self,
        request: &FinishRecording,
    ) -> Result<RecordingCompletion, PortError> {
        // One admission scope per store call (ADR 0008 Amendment 1); never held across calls.
        let _scope = xtrace_private_storage::AdmissionScope::enter();
        let view =
            self.store.recording_store(&self.project_data_root).map_err(map_recording_error)?;
        view.finish_recording(request).map_err(map_recording_error)
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
    use xtrace_protocol::generated::agent::SourceBinding as WireSourceBinding;
    let binding = WireSourceBinding::try_from(payload.source_binding).map_err(|_| {
        PortError::new(
            PortErrorKind::Validation,
            "recording source binding is invalid",
            CorrelationId::new(),
        )
    })?;
    let invalid_source = || {
        PortError::new(
            PortErrorKind::Validation,
            "recording source metadata is invalid",
            CorrelationId::new(),
        )
    };
    let mismatched = || {
        PortError::new(
            PortErrorKind::Validation,
            "recording source binding disagrees with source metadata",
            CorrelationId::new(),
        )
    };
    let extent_ok = |source: &xtrace_protocol::generated::agent::SourceRange| {
        source.start_line != 0 && (source.end_line == 0 || source.end_line >= source.start_line)
    };
    match (binding, payload.source.as_ref()) {
        (WireSourceBinding::Verified | WireSourceBinding::ObservedUnattested, Some(source)) => {
            if !xtrace_domain::is_safe_repo_relative_path(&source.path)
                || source.content_hash.len() != 32
                || !extent_ok(source)
            {
                return Err(invalid_source());
            }
        }
        (
            WireSourceBinding::SourceMapAbsent | WireSourceBinding::SourceMapUnresolved,
            Some(source),
        ) => {
            if !xtrace_domain::is_safe_repo_relative_path(&source.path)
                || (!source.content_hash.is_empty() && source.content_hash.len() != 32)
                || !extent_ok(source)
            {
                return Err(invalid_source());
            }
        }
        // CONTRACTS section 3 rule 6: source is present iff the binding has a source claim.
        (
            WireSourceBinding::Verified
            | WireSourceBinding::ObservedUnattested
            | WireSourceBinding::SourceMapAbsent
            | WireSourceBinding::SourceMapUnresolved,
            None,
        )
        | (
            WireSourceBinding::AttestationMissing
            | WireSourceBinding::ClassBytesMismatch
            | WireSourceBinding::DebugMetadataAbsent
            | WireSourceBinding::SourceMetadataInvalid
            | WireSourceBinding::Unspecified,
            Some(_),
        ) => return Err(mismatched()),
        _ => {}
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
        RecordEvents, RecordingCapture, RecordingCaptureService, RecordingCompletion,
        RecordingPersistencePort, SegmentPolicy,
    };
    use xtrace_application::recording_queries::{
        ListRecordings, RecordingReadPort, ShowRecording, ShowWindowRequest,
    };
    use xtrace_domain::ids::Id as _;
    use xtrace_domain::{
        CapturedValue, ContentHash, CorrelationId, Project, ProjectId, RecordingId,
        RepositoryFingerprint, RuntimeSessionId, SafePreview, ValueShape, WallTime,
    };
    use xtrace_protocol::generated::agent::{ExceptionPayload, Interaction, RecordingEvent};
    use xtrace_protocol::xtf::XtfEventEnvelope;

    use crate::{OpenOptions, SqliteRecordingPersistence, SqliteRecordingReader, SqliteStore};

    fn fixture() -> (tempfile::TempDir, SqliteStore, Project) {
        let temp_base = std::path::PathBuf::from(
            std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
                .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required"),
        );
        xtrace_private_storage::AdmittedPrivateRoot::open(&temp_base)
            .expect("admitted private test scratch");
        let directory = tempfile::Builder::new()
            .prefix("recording-port-")
            .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
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
            endpoint_observation: xtrace_application::recording::EndpointObservationInput::default(
            ),
        }
    }

    fn event(sequence: u64, event_id: &str) -> AcceptedRecordingEvent<XtfEventEnvelope> {
        event_with_priority(sequence, event_id, 1)
    }

    fn event_with_priority(
        sequence: u64,
        event_id: &str,
        priority: u32,
    ) -> AcceptedRecordingEvent<XtfEventEnvelope> {
        let nested = RecordingEvent {
            event_id: event_id.to_owned(),
            recording_seq: sequence,
            monotonic_ns: sequence * 10,
            priority,
            ..RecordingEvent::default()
        };
        let payload = XtfEventEnvelope { recording_seq: sequence, event: Some(nested) };
        let canonical_bytes = payload.encode_to_vec();
        AcceptedRecordingEvent {
            recording_seq: sequence,
            monotonic_ns: sequence * 10,
            priority,
            canonical_bytes,
            payload,
        }
    }

    fn source_event(
        binding: xtrace_protocol::generated::agent::SourceBinding,
        path: &str,
        hash_len: usize,
    ) -> AcceptedRecordingEvent<XtfEventEnvelope> {
        let mut accepted = event(2, "evt-src");
        let nested = accepted.payload.event.as_mut().expect("typed payload");
        nested.source_binding = binding as i32;
        nested.source = Some(xtrace_protocol::generated::agent::SourceRange {
            path: path.to_owned(),
            start_line: 2,
            end_line: 3,
            content_hash: vec![7; hash_len].into(),
            ..Default::default()
        });
        accepted.canonical_bytes = accepted.payload.encode_to_vec();
        accepted
    }

    #[test]
    fn write_gate_accepts_generic_verified_and_unattested_sources() {
        use xtrace_protocol::generated::agent::SourceBinding as B;
        for binding in [B::Verified, B::ObservedUnattested] {
            let accepted =
                source_event(binding, "services/petclinic/src/main/java/org/p/Owner.java", 32);
            super::validate_xtf_event(&accepted).expect("generic source path accepted");
        }
        let mapped = source_event(B::SourceMapUnresolved, "src/routes/users.ts", 0);
        super::validate_xtf_event(&mapped).expect("mapped path without hash accepted");
    }

    #[test]
    fn write_gate_refuses_unsafe_paths_and_mismatched_bindings() {
        use xtrace_protocol::generated::agent::SourceBinding as B;
        for path in [
            "../x/A.java",
            "src/./A.java",
            "/abs/A.java",
            "C:/x/A.java",
            "src/\u{1b}[2J/A.java",
            "src/\tA.java",
            "src/\u{7f}A.java",
        ] {
            let accepted = source_event(B::Verified, path, 32);
            assert!(super::validate_xtf_event(&accepted).is_err(), "{path:?} must be refused");
        }
        let too_long = format!("{}.java", "a".repeat(1025));
        assert!(super::validate_xtf_event(&source_event(B::Verified, &too_long, 32)).is_err());
        let long_ok = format!("{}/A.java", "a".repeat(1000));
        super::validate_xtf_event(&source_event(B::Verified, &long_ok, 32))
            .expect("paths up to 1024 bytes are accepted");
        // Extension and dot-directory rules are read-projection rules, not write rules: a
        // refused write would reject the whole batch.
        for path in [".env", "config/.env.ts", "README.md"] {
            let result = super::validate_xtf_event(&source_event(B::Verified, path, 32));
            assert!(result.is_ok(), "{path} is accepted at write time");
        }
        for binding in [B::SourceMapAbsent, B::SourceMapUnresolved] {
            let mut missing = source_event(binding, "src/A.ts", 0);
            missing.payload.event.as_mut().expect("typed").source = None;
            missing.canonical_bytes = missing.payload.encode_to_vec();
            assert!(super::validate_xtf_event(&missing).is_err(), "{binding:?} needs a source");
        }
        assert!(super::validate_xtf_event(&source_event(B::Verified, "src/A.java", 31)).is_err());
        assert!(
            super::validate_xtf_event(&source_event(B::AttestationMissing, "src/A.java", 32))
                .is_err()
        );
        let mut missing = source_event(B::ObservedUnattested, "src/A.java", 32);
        missing.payload.event.as_mut().expect("typed").source = None;
        missing.canonical_bytes = missing.payload.encode_to_vec();
        assert!(super::validate_xtf_event(&missing).is_err());
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
    fn terminal_evidence_and_frame_ids_survive_exact_retry_and_reopen() {
        let (directory, store, project) = fixture();
        let recording_id = RecordingId::new();
        let begin_request = begin(project.id(), recording_id);
        let adapter = SqliteRecordingPersistence::new(store.clone(), directory.path());
        adapter.begin_recording(&begin_request).expect("begin recording");
        let events = [event(2, "event-2"), event(3, "event-3")];
        let first_segment = PersistRecordingSegment {
            project_id: project.id(),
            recording_id,
            segment_ordinal: 0,
            events: vec![events[0].clone()],
        };
        let second_segment = PersistRecordingSegment {
            project_id: project.id(),
            recording_id,
            segment_ordinal: 1,
            events: vec![events[1].clone()],
        };
        adapter.persist_segment(&first_segment).expect("persist first segment");
        adapter.persist_segment(&second_segment).expect("persist second segment");
        let finish = FinishRecording {
            recording_id,
            final_recording_seq: 3,
            duration_ns: Some(77),
            event_digest: blake3::hash(b"event-2event-3").as_bytes().to_vec(),
            drop_counts_by_priority: [(1, 0)].into_iter().collect(),
            unsupported_capability_codes: vec!["focused_locals".to_string()],
            capacity_dropped_events: 0,
            event_cap: 2_048,
            outcome: None,
            response_summary: Some(CapturedValue::Redacted {
                rule_id: "unverified-producer-redaction".to_string(),
                shape_hint: Some(ValueShape::String),
            }),
        };
        let mut unsafe_finish = finish.clone();
        unsafe_finish.response_summary = Some(CapturedValue::Captured {
            shape: ValueShape::String,
            preview: SafePreview::from_redacted_unchecked("private-finish-canary"),
            digest: ContentHash::of_bytes(b"private-finish-canary"),
        });
        let unsafe_error = adapter
            .finish_recording(&unsafe_finish)
            .expect_err("unverified producer preview cannot enter durable projection");
        assert!(unsafe_error.message().contains("XTR-STORE-RECORDING-FINISH-VALIDATION"));
        assert_eq!(
            adapter.finish_recording(&finish).expect("verified finish"),
            RecordingCompletion::Complete,
        );
        assert_eq!(
            adapter.finish_recording(&finish).expect("exact finish retry"),
            RecordingCompletion::Complete
        );

        let reader = SqliteRecordingReader::new(store.clone(), directory.path());
        let request = ShowWindowRequest {
            project_id: project.id(),
            recording_id,
            limit: 10,
            after_sequence: None,
        };
        let first_window = reader.show_recording(&request).expect("read indexed frames");
        assert_eq!(
            first_window.completion,
            xtrace_application::recording_queries::RecordingCompletionEvidence::Complete
        );
        assert_eq!(first_window.adapter_summary, finish.response_summary);
        assert_eq!(first_window.duration_ns.as_deref(), Some("77"));
        assert_eq!(first_window.drop_counts_by_priority.get(&1).map(String::as_str), Some("0"));
        assert_eq!(first_window.events.len(), 2);
        let first_frame = first_window.events[0].frame_id.expect("first frame index");
        let second_frame = first_window.events[1].frame_id.expect("second frame index");
        assert_eq!(
            first_window.events[0].navigation.previous,
            xtrace_application::recording_queries::NavigationResult::Boundary
        );
        assert_eq!(
            first_window.events[0].navigation.next,
            xtrace_application::recording_queries::NavigationResult::Target {
                frame_id: second_frame
            }
        );
        assert_eq!(
            first_window.events[1].navigation.previous,
            xtrace_application::recording_queries::NavigationResult::Target {
                frame_id: first_frame
            }
        );
        assert_eq!(
            first_window.events[1].navigation.next,
            xtrace_application::recording_queries::NavigationResult::Boundary
        );
        // Indexed rows resolve into/over/out from the v8 index: with no child, `into` falls
        // back to `next`; `over` is the next frame at the same depth; a root's `out` is the boundary.
        assert_eq!(
            first_window.events[0].navigation.into,
            xtrace_application::recording_queries::NavigationResult::Target {
                frame_id: second_frame
            }
        );
        assert_eq!(
            first_window.events[0].navigation.over,
            xtrace_application::recording_queries::NavigationResult::Target {
                frame_id: second_frame
            }
        );
        assert_eq!(
            first_window.events[0].navigation.out,
            xtrace_application::recording_queries::NavigationResult::Boundary
        );
        let second_page = reader
            .show_recording(&ShowWindowRequest { limit: 1, after_sequence: Some(2), ..request })
            .expect("read page beginning at a segment boundary");
        assert_eq!(second_page.events[0].frame_id, Some(second_frame));
        assert_eq!(
            second_page.events[0].navigation.previous,
            xtrace_application::recording_queries::NavigationResult::Target {
                frame_id: first_frame
            }
        );
        assert_eq!(
            second_page.events[0].navigation.next,
            xtrace_application::recording_queries::NavigationResult::Boundary
        );

        drop(reader);
        drop(adapter);
        drop(store);
        let reopened =
            SqliteStore::open(&directory.path().join("metadata.sqlite3"), OpenOptions::default())
                .expect("reopen selected SQLite store");
        let reopened_adapter = SqliteRecordingPersistence::new(reopened.clone(), directory.path());
        assert_eq!(
            reopened_adapter.finish_recording(&finish).expect("terminal retry after reopen"),
            RecordingCompletion::Complete
        );
        let reopened_reader = SqliteRecordingReader::new(reopened.clone(), directory.path());
        let reopened_window = reopened_reader.show_recording(&request).expect("read after reopen");
        assert_eq!(reopened_window.duration_ns.as_deref(), Some("77"));
        assert_eq!(reopened_window.drop_counts_by_priority.get(&1).map(String::as_str), Some("0"));
        assert_eq!(reopened_window.adapter_summary, finish.response_summary);
        assert_eq!(
            reopened_window.events.iter().map(|event| event.frame_id).collect::<Vec<_>>(),
            vec![Some(first_frame), Some(second_frame)],
        );
        let (metadata, _) =
            reopened_reader.list_recordings(project.id(), None, 10).expect("list after reopen");
        assert_eq!(
            metadata[0].completion,
            xtrace_application::recording_queries::RecordingCompletionEvidence::Complete
        );

        let connection = reopened.lock().expect("metadata connection");
        connection
            .execute(
                "UPDATE recording_frame_index SET event_id_digest = zeroblob(32) \
             WHERE recording_id = ?1 AND recording_seq = ?2",
                rusqlite::params![
                    recording_id.as_uuid().as_bytes().to_vec(),
                    2_u64.to_be_bytes().as_slice(),
                ],
            )
            .expect("corrupt only the page lookbehind index");
        drop(connection);
        let corrupted_lookbehind = reopened_reader
            .show_recording(&ShowWindowRequest { limit: 1, after_sequence: Some(2), ..request })
            .expect("corrupt optional lookbehind degrades to unavailable");
        assert_eq!(corrupted_lookbehind.events[0].frame_id, Some(second_frame));
        assert_eq!(
            corrupted_lookbehind.events[0].navigation.previous,
            xtrace_application::recording_queries::NavigationResult::unavailable(
                xtrace_application::recording_queries::NavigationUnavailable::PartialFrontier,
            )
        );

        let connection = reopened.lock().expect("metadata connection");
        connection
            .execute(
                "UPDATE recording_frame_index SET event_id_digest = ?1 \
             WHERE recording_id = ?2 AND recording_seq = ?3",
                rusqlite::params![
                    blake3::hash(b"event-2").as_bytes().as_slice(),
                    recording_id.as_uuid().as_bytes().to_vec(),
                    2_u64.to_be_bytes().as_slice(),
                ],
            )
            .expect("restore the valid lookbehind index");
        connection
            .execute(
                "UPDATE recording_frame_index SET event_id_digest = zeroblob(32) \
             WHERE recording_id = ?1 AND recording_seq = ?2",
                rusqlite::params![
                    recording_id.as_uuid().as_bytes().to_vec(),
                    3_u64.to_be_bytes().as_slice(),
                ],
            )
            .expect("corrupt only the neighboring metadata index");
        drop(connection);
        let corrupted_neighbor = reopened_reader
            .show_recording(&request)
            .expect("corrupt optional navigation degrades to unavailable");
        assert_eq!(corrupted_neighbor.events[0].frame_id, Some(first_frame));
        assert_eq!(
            corrupted_neighbor.events[0].navigation.next,
            xtrace_application::recording_queries::NavigationResult::unavailable(
                xtrace_application::recording_queries::NavigationUnavailable::PartialFrontier,
            )
        );
        assert_eq!(corrupted_neighbor.events[1].frame_id, None);
    }

    #[test]
    fn invalid_terminal_proof_suppresses_summary_and_unverified_end_boundary() {
        let (directory, store, project) = fixture();
        let recording_id = RecordingId::new();
        let persistence = SqliteRecordingPersistence::new(store.clone(), directory.path());
        persistence.begin_recording(&begin(project.id(), recording_id)).expect("begin");
        persistence
            .persist_segment(&PersistRecordingSegment {
                project_id: project.id(),
                recording_id,
                segment_ordinal: 0,
                events: vec![event(2, "event-2")],
            })
            .expect("persist event");
        let finish = FinishRecording {
            recording_id,
            final_recording_seq: 2,
            duration_ns: None,
            event_digest: vec![9; 32],
            drop_counts_by_priority: std::collections::BTreeMap::new(),
            unsupported_capability_codes: Vec::new(),
            capacity_dropped_events: 0,
            event_cap: 2_048,
            outcome: None,
            response_summary: Some(CapturedValue::Redacted {
                rule_id: "unverified-producer-redaction".to_string(),
                shape_hint: None,
            }),
        };
        assert_eq!(
            persistence.finish_recording(&finish).expect("invalid proof is durable"),
            RecordingCompletion::Invalid
        );
        let reader = SqliteRecordingReader::new(store.clone(), directory.path());
        let window = reader
            .show_recording(&ShowWindowRequest {
                project_id: project.id(),
                recording_id,
                limit: 10,
                after_sequence: None,
            })
            .expect("read invalid terminal capture");
        assert_eq!(
            window.completion,
            xtrace_application::recording_queries::RecordingCompletionEvidence::Invalid
        );
        assert_eq!(window.adapter_summary, None);
        assert_eq!(
            window.events[0].navigation.next,
            xtrace_application::recording_queries::NavigationResult::unavailable(
                xtrace_application::recording_queries::NavigationUnavailable::PartialFrontier,
            )
        );

        let partial_id = RecordingId::new();
        let partial_persistence = SqliteRecordingPersistence::new(store.clone(), directory.path());
        partial_persistence
            .begin_recording(&begin(project.id(), partial_id))
            .expect("begin partial");
        partial_persistence
            .persist_segment(&PersistRecordingSegment {
                project_id: project.id(),
                recording_id: partial_id,
                segment_ordinal: 0,
                events: vec![event(2, "event-partial")],
            })
            .expect("persist partial event");
        assert_eq!(
            partial_persistence
                .finish_recording(&FinishRecording::without_digest(partial_id, 2))
                .expect("missing proof remains partial"),
            RecordingCompletion::Partial
        );
        let partial_window = reader
            .show_recording(&ShowWindowRequest {
                project_id: project.id(),
                recording_id: partial_id,
                limit: 10,
                after_sequence: None,
            })
            .expect("read partial finish");
        assert_eq!(
            partial_window.events[0].navigation.next,
            xtrace_application::recording_queries::NavigationResult::unavailable(
                xtrace_application::recording_queries::NavigationUnavailable::PartialFrontier,
            )
        );
    }

    #[test]
    fn read_rejects_capacity_drops_inconsistent_with_a_full_history() {
        // capacity_dropped_events > 0 requires a full persisted history
        // (event_count == MAX_RECORDED_EVENTS) and an absent adapter digest.
        let (directory, store, project) = fixture();
        let persistence = SqliteRecordingPersistence::new(store.clone(), directory.path());
        let reader = SqliteRecordingReader::new(store, directory.path());
        let recording_id = RecordingId::new();
        persistence.begin_recording(&begin(project.id(), recording_id)).expect("begin");
        persistence
            .persist_segment(&PersistRecordingSegment {
                project_id: project.id(),
                recording_id,
                segment_ordinal: 0,
                events: vec![event(2, "event-2")],
            })
            .expect("persist event");
        let finish = FinishRecording {
            recording_id,
            final_recording_seq: 4,
            duration_ns: None,
            event_digest: Vec::new(),
            drop_counts_by_priority: [(1, 2)].into_iter().collect(),
            unsupported_capability_codes: Vec::new(),
            capacity_dropped_events: 2,
            event_cap: 2_048,
            outcome: None,
            response_summary: None,
        };
        assert_eq!(
            persistence.finish_recording(&finish).expect("finish stores the evidence"),
            RecordingCompletion::Partial
        );
        let error = reader
            .show_recording(&ShowWindowRequest {
                project_id: project.id(),
                recording_id,
                limit: 10,
                after_sequence: None,
            })
            .expect_err("one persisted event cannot have come from a full history");
        assert_eq!(error.kind(), PortErrorKind::Corruption);
    }

    #[test]
    fn capacity_drops_at_a_full_history_require_an_absent_adapter_digest() {
        use xtrace_application::recording::MAX_RECORDED_EVENTS;
        let (directory, store, project) = fixture();
        let persistence = SqliteRecordingPersistence::new(store.clone(), directory.path());
        let reader = SqliteRecordingReader::new(store, directory.path());
        let last_kept = 1 + MAX_RECORDED_EVENTS as u64;
        for (digest, expect_corruption) in [(vec![9_u8; 32], true), (Vec::new(), false)] {
            let recording_id = RecordingId::new();
            persistence.begin_recording(&begin(project.id(), recording_id)).expect("begin");
            let events = (2..=last_kept)
                .map(|sequence| event(sequence, &format!("event-{sequence}")))
                .collect::<Vec<_>>();
            for (ordinal, chunk) in events.chunks(1_000).enumerate() {
                persistence
                    .persist_segment(&PersistRecordingSegment {
                        project_id: project.id(),
                        recording_id,
                        segment_ordinal: u32::try_from(ordinal).expect("small ordinal"),
                        events: chunk.to_vec(),
                    })
                    .expect("persist full history");
            }
            persistence
                .finish_recording(&FinishRecording {
                    recording_id,
                    final_recording_seq: last_kept + 1,
                    duration_ns: None,
                    event_digest: digest,
                    drop_counts_by_priority: [(1, 1)].into_iter().collect(),
                    unsupported_capability_codes: Vec::new(),
                    capacity_dropped_events: 1,
                    event_cap: 2_048,
                    outcome: None,
                    response_summary: None,
                })
                .expect("finish stores the evidence");
            let result = reader.show_recording(&ShowWindowRequest {
                project_id: project.id(),
                recording_id,
                limit: 10,
                after_sequence: None,
            });
            if expect_corruption {
                let error =
                    result.expect_err("a present adapter digest contradicts capacity drops");
                assert_eq!(error.kind(), PortErrorKind::Corruption);
            } else {
                let window = result.expect("full history with withheld digest reads back");
                assert_eq!(
                    window.completion,
                    xtrace_application::recording_queries::RecordingCompletionEvidence::Partial
                );
            }
        }
    }

    #[test]
    fn read_rejects_complete_labels_without_complete_finish_proof() {
        let (directory, store, project) = fixture();
        let persistence = SqliteRecordingPersistence::new(store.clone(), directory.path());
        let reader = SqliteRecordingReader::new(store.clone(), directory.path());

        let proof_digest = blake3::hash(b"event-2").as_bytes().to_vec();
        let finish_cases = [
            (
                RecordingId::new(),
                Vec::new(),
                std::collections::BTreeMap::new(),
                RecordingCompletion::Partial,
            ),
            (
                RecordingId::new(),
                vec![9; 31],
                std::collections::BTreeMap::new(),
                RecordingCompletion::Invalid,
            ),
            (
                RecordingId::new(),
                vec![0; 32],
                std::collections::BTreeMap::new(),
                RecordingCompletion::Partial,
            ),
            (
                RecordingId::new(),
                proof_digest,
                [(1, 1)].into_iter().collect(),
                RecordingCompletion::Partial,
            ),
        ];
        for (recording_id, event_digest, drop_counts_by_priority, expected_completion) in
            finish_cases
        {
            let finish = FinishRecording {
                recording_id,
                final_recording_seq: 2,
                duration_ns: None,
                event_digest,
                drop_counts_by_priority,
                unsupported_capability_codes: Vec::new(),
                capacity_dropped_events: 0,
                event_cap: 2_048,
                outcome: None,
                response_summary: None,
            };
            persistence.begin_recording(&begin(project.id(), recording_id)).expect("begin");
            persistence
                .persist_segment(&PersistRecordingSegment {
                    project_id: project.id(),
                    recording_id,
                    segment_ordinal: 0,
                    events: vec![event(2, "event-2")],
                })
                .expect("persist event");
            assert_eq!(
                persistence.finish_recording(&finish).expect("persist non-complete finish"),
                expected_completion,
            );

            let connection = store.lock().expect("metadata connection");
            connection
                .execute(
                    "UPDATE recordings SET status = 'complete' WHERE recording_id = ?1",
                    rusqlite::params![recording_id.as_uuid().as_bytes().to_vec()],
                )
                .expect("corrupt lifecycle label");
            connection
                .execute(
                    "UPDATE recording_terminal_evidence SET completion = 'complete' WHERE recording_id = ?1",
                    rusqlite::params![recording_id.as_uuid().as_bytes().to_vec()],
                )
                .expect("corrupt terminal label");
            drop(connection);

            let error = reader
                .show_recording(&ShowWindowRequest {
                    project_id: project.id(),
                    recording_id,
                    limit: 10,
                    after_sequence: None,
                })
                .expect_err("two matching labels cannot replace terminal proof");
            assert_eq!(error.kind(), PortErrorKind::Corruption);
        }
    }

    #[test]
    fn read_adapter_pages_and_projects_only_verified_persisted_fields() {
        let (directory, store, project) = fixture();
        let persistence = SqliteRecordingPersistence::new(store.clone(), directory.path());
        let reader = SqliteRecordingReader::new(store.clone(), directory.path());
        let first = begin(project.id(), RecordingId::new());
        let second = begin(project.id(), RecordingId::new());
        persistence.begin_recording(&first).expect("first anchor");
        persistence.begin_recording(&second).expect("second anchor");
        let mut sensitive = event(2, "persisted-event");
        let mut nested = sensitive.payload.event.take().expect("event payload");
        nested.kind = i32::MAX;
        nested.async_parent_event_id = "async-parent-event".to_owned();
        nested.exception = Some(ExceptionPayload {
            exception_type: "SafeException".to_owned(),
            sanitized_message: "VALUE_CANARY_RECORDING_READ".to_owned(),
            stack_frames: vec!["secret/Source.java:1".to_owned()],
        });
        nested.interaction = Some(Interaction {
            kind: 2,
            method: "GET".to_owned(),
            path: "/orders/PATH_SEGMENT_CANARY?QUERY_CANARY#FRAGMENT_CANARY".to_owned(),
            ..Interaction::default()
        });
        sensitive.payload = XtfEventEnvelope { recording_seq: 2, event: Some(nested) };
        sensitive.canonical_bytes = sensitive.payload.encode_to_vec();
        persistence
            .persist_segment(&PersistRecordingSegment {
                project_id: project.id(),
                recording_id: first.recording_id,
                segment_ordinal: 0,
                events: vec![sensitive, event(3, "second-event")],
            })
            .expect("persist first segment");
        persistence
            .persist_segment(&PersistRecordingSegment {
                project_id: project.id(),
                recording_id: second.recording_id,
                segment_ordinal: 0,
                events: vec![event(2, "other-event")],
            })
            .expect("persist second segment");
        rusqlite::Connection::open(directory.path().join("metadata.sqlite3"))
            .expect("open status fixture")
            .execute(
                "UPDATE recordings SET status = 'partial' WHERE recording_id = ?1",
                rusqlite::params![first.recording_id.as_uuid().as_bytes().to_vec()],
            )
            .expect("mark persisted partial status");

        let page = xtrace_application::list_recordings(
            &reader,
            ListRecordings { project_id: project.id(), limit: 1, after: None },
            CorrelationId::new(),
        )
        .expect("first page");
        assert_eq!(page.recordings.len(), 1);
        assert!(page.next_after.is_some());
        let next = xtrace_application::list_recordings(
            &reader,
            ListRecordings { project_id: project.id(), limit: 1, after: page.next_after },
            CorrelationId::new(),
        )
        .expect("next page");
        assert_eq!(next.recordings.len(), 1);
        assert_ne!(next.recordings[0].recording_id, page.recordings[0].recording_id);

        let detail = xtrace_application::show_recording(
            &reader,
            ShowRecording {
                project_id: project.id(),
                recording_id: first.recording_id,
                limit: 1,
                cursor: None,
                around_frame: None,
            },
            CorrelationId::new(),
        )
        .expect("verified event window");
        assert_eq!(detail.events.len(), 1);
        assert_eq!(detail.events[0].sequence, "2");
        assert_eq!(detail.events[0].kind, "unknown:2147483647");
        assert_eq!(detail.events[0].async_parent_event_id.as_deref(), Some("async-parent-event"));
        assert!(detail.events[0].field_truncations.is_empty());
        assert!(detail.events[0].interaction.as_ref().is_some_and(|interaction| {
            !serde_json::to_value(interaction)
                .expect("interaction JSON")
                .as_object()
                .is_some_and(|fields| fields.contains_key("path"))
        }));
        assert_eq!(detail.incomplete_evidence, ["persisted_status:partial"]);
        let next_cursor = detail.next_cursor.clone().expect("bounded next window cursor");
        let rendered = serde_json::to_string(&detail).expect("render detail");
        assert!(!rendered.contains("VALUE_CANARY_RECORDING_READ"));
        assert!(!rendered.contains("Source.java"));
        assert!(!rendered.contains("/orders"));
        assert!(!rendered.contains("PATH_SEGMENT_CANARY"));
        assert!(!rendered.contains("QUERY_CANARY"));
        assert!(!rendered.contains("FRAGMENT_CANARY"));
        assert!(!rendered.contains("\"path\""));
        assert!(rendered.contains("completion"));

        let next_detail = xtrace_application::show_recording(
            &reader,
            ShowRecording {
                project_id: project.id(),
                recording_id: first.recording_id,
                limit: 10,
                cursor: Some(next_cursor),
                around_frame: None,
            },
            CorrelationId::new(),
        )
        .expect("cursor continues in sequence order");
        assert_eq!(next_detail.events[0].sequence, "3");
        assert!(next_detail.next_cursor.is_none());
    }

    #[test]
    fn projection_budget_pages_across_segments_and_oversized_events_remain_reachable() {
        let (directory, store, project) = fixture();
        let persistence = SqliteRecordingPersistence::new(store.clone(), directory.path());
        let reader = SqliteRecordingReader::new(store.clone(), directory.path());
        let request = begin(project.id(), RecordingId::new());
        persistence.begin_recording(&request).expect("recording anchor");
        for (ordinal, sequence) in [(0, 2), (1, 3)] {
            let mut event = event(sequence, &format!("wide-{sequence}"));
            event.payload.event.as_mut().expect("event payload").symbol = "x".repeat(150_000);
            let payload = event.payload;
            store
                .recording_store(directory.path())
                .expect("bound store")
                .commit_segment(&crate::SegmentCommitRequest {
                    project_id: project.id(),
                    recording_id: request.recording_id,
                    segment_ordinal: ordinal,
                    events: vec![payload],
                })
                .expect("persist wide segment");
        }

        let first = xtrace_application::show_recording(
            &reader,
            ShowRecording {
                project_id: project.id(),
                recording_id: request.recording_id,
                limit: 1,
                cursor: None,
                around_frame: None,
            },
            CorrelationId::new(),
        )
        .expect("first byte-bounded window");
        assert_eq!(first.events.len(), 1);
        let cursor = first.next_cursor.expect("next byte-bounded window");
        let second = xtrace_application::show_recording(
            &reader,
            ShowRecording {
                project_id: project.id(),
                recording_id: request.recording_id,
                limit: 1,
                cursor: Some(cursor),
                around_frame: None,
            },
            CorrelationId::new(),
        )
        .expect("second segment window");
        assert_eq!(second.events.len(), 1);
        assert_eq!(second.events[0].sequence, "3");
        assert!(second.next_cursor.is_none());

        let oversized_id = RecordingId::new();
        let oversized_request = begin(project.id(), oversized_id);
        persistence.begin_recording(&oversized_request).expect("oversized recording anchor");
        let mut huge = event(2, "too-wide");
        huge.payload.event.as_mut().expect("event payload").symbol = format!(
            "OVERSIZED_SYMBOL_CANARY{}",
            "x".repeat(xtrace_application::MAX_RECORDING_EVENT_PROJECTION_BYTES + 1)
        );
        store
            .recording_store(directory.path())
            .expect("bound store")
            .commit_segment(&crate::SegmentCommitRequest {
                project_id: project.id(),
                recording_id: oversized_id,
                segment_ordinal: 0,
                events: vec![huge.payload, event(3, "later-event").payload],
            })
            .expect("persist oversized event");
        let first = xtrace_application::show_recording(
            &reader,
            ShowRecording {
                project_id: project.id(),
                recording_id: oversized_id,
                limit: 1,
                cursor: None,
                around_frame: None,
            },
            CorrelationId::new(),
        )
        .expect("large display event is safely represented");
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.events[0].sequence, "2");
        assert_eq!(first.events[0].symbol.as_deref(), Some("[truncated]"));
        assert!(first.events[0].field_truncations.iter().any(|field| field.field == "symbol"));
        let rendered = serde_json::to_string(&first).expect("bounded first event");
        assert!(!rendered.contains("OVERSIZED_SYMBOL_CANARY"));
        let second = xtrace_application::show_recording(
            &reader,
            ShowRecording {
                project_id: project.id(),
                recording_id: oversized_id,
                limit: 1,
                cursor: first.next_cursor,
                around_frame: None,
            },
            CorrelationId::new(),
        )
        .expect("later event remains reachable");
        assert_eq!(second.events[0].sequence, "3");
        assert!(second.next_cursor.is_none());
    }

    #[test]
    fn verified_input_budget_pages_large_segments_losslessly() {
        let (directory, store, project) = fixture();
        let persistence = SqliteRecordingPersistence::new(store.clone(), directory.path());
        let reader = SqliteRecordingReader::new(store.clone(), directory.path());
        let request = begin(project.id(), RecordingId::new());
        persistence.begin_recording(&request).expect("recording anchor");
        let mut next_sequence = 2_u64;
        for ordinal in 0..7_u32 {
            let mut events = Vec::new();
            for _ in 0..10 {
                let mut item = event(next_sequence, &format!("large-{next_sequence}"));
                item.payload.event.as_mut().expect("event payload").symbol = "x".repeat(350_000);
                item.canonical_bytes = item.payload.encode_to_vec();
                events.push(item);
                next_sequence += 1;
            }
            persistence
                .persist_segment(&PersistRecordingSegment {
                    project_id: project.id(),
                    recording_id: request.recording_id,
                    segment_ordinal: ordinal,
                    events,
                })
                .expect("persist near-limit logical segment");
        }

        let first = xtrace_application::show_recording(
            &reader,
            ShowRecording {
                project_id: project.id(),
                recording_id: request.recording_id,
                limit: 100,
                cursor: None,
                around_frame: None,
            },
            CorrelationId::new(),
        )
        .expect("first verified-input-bounded page");
        assert_eq!(first.events.len(), 40, "four logical segments fit the work budget");
        let first_cursor = first.next_cursor.clone().expect("bounded continuation");

        let second = xtrace_application::show_recording(
            &reader,
            ShowRecording {
                project_id: project.id(),
                recording_id: request.recording_id,
                limit: 100,
                cursor: Some(first_cursor),
                around_frame: None,
            },
            CorrelationId::new(),
        )
        .expect("continued verified-input-bounded page");
        assert_eq!(second.events.len(), 30);
        assert!(second.next_cursor.is_none());
        let sequences = first
            .events
            .into_iter()
            .chain(second.events)
            .map(|event| event.sequence.parse::<u64>().expect("decimal sequence"))
            .collect::<Vec<_>>();
        assert_eq!(sequences, (2_u64..72).collect::<Vec<_>>());
    }

    #[test]
    fn projection_response_byte_limit_continues_within_a_segment() {
        let (directory, store, project) = fixture();
        let persistence = SqliteRecordingPersistence::new(store.clone(), directory.path());
        let reader = SqliteRecordingReader::new(store.clone(), directory.path());
        let request = begin(project.id(), RecordingId::new());
        persistence.begin_recording(&request).expect("recording anchor");
        let events = (2_u64..802)
            .map(|sequence| {
                let mut item = event(sequence, &format!("event-{sequence}"));
                item.payload.event.as_mut().expect("event payload").symbol = "s".repeat(220);
                item.canonical_bytes = item.payload.encode_to_vec();
                item
            })
            .collect();
        persistence
            .persist_segment(&PersistRecordingSegment {
                project_id: project.id(),
                recording_id: request.recording_id,
                segment_ordinal: 0,
                events,
            })
            .expect("persist bounded display fields");

        let mut cursor = None;
        let mut sequences = Vec::new();
        let mut pages = 0;
        loop {
            let page = xtrace_application::show_recording(
                &reader,
                ShowRecording {
                    project_id: project.id(),
                    recording_id: request.recording_id,
                    limit: 1_000,
                    cursor,
                    around_frame: None,
                },
                CorrelationId::new(),
            )
            .expect("projection-byte-bounded page");
            assert!(!page.events.is_empty(), "each bounded page makes forward progress");
            sequences.extend(
                page.events
                    .into_iter()
                    .map(|event| event.sequence.parse::<u64>().expect("decimal sequence")),
            );
            pages += 1;
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
            assert!(pages < 800, "pagination must remain bounded and advance");
        }
        assert!(pages >= 2, "large projection is split across bounded pages");
        assert_eq!(sequences.len(), 800);
        assert_eq!(sequences, (2_u64..802).collect::<Vec<_>>());
    }

    #[test]
    fn read_adapter_hides_cross_project_ids_and_rejects_missing_or_corrupt_objects() {
        let (directory, store, project) = fixture();
        let persistence = SqliteRecordingPersistence::new(store.clone(), directory.path());
        let reader = SqliteRecordingReader::new(store.clone(), directory.path());
        let request = begin(project.id(), RecordingId::new());
        persistence.begin_recording(&request).expect("anchor");
        let receipt = store
            .recording_store(directory.path())
            .expect("bound store")
            .commit_segment(&crate::SegmentCommitRequest {
                project_id: project.id(),
                recording_id: request.recording_id,
                segment_ordinal: 0,
                events: vec![event(2, "verified").payload],
            })
            .expect("committed segment");
        let request_for = |project_id| ShowWindowRequest {
            project_id,
            recording_id: request.recording_id,
            limit: 10,
            after_sequence: None,
        };
        let unknown = reader
            .show_recording(&ShowWindowRequest {
                project_id: project.id(),
                recording_id: RecordingId::new(),
                limit: 10,
                after_sequence: None,
            })
            .expect_err("unknown recording is rejected");
        assert_eq!(unknown.kind(), PortErrorKind::NotFound);
        let other_project = ProjectId::new();
        let hidden = reader
            .show_recording(&request_for(other_project))
            .expect_err("cross-project identity is hidden");
        assert_eq!(hidden.kind(), PortErrorKind::NotFound);

        let connection = rusqlite::Connection::open(directory.path().join("metadata.sqlite3"))
            .expect("open metadata fixture");
        connection
            .execute(
                "UPDATE recording_segments SET first_recording_seq = ?1, last_recording_seq = ?1 \
                 WHERE recording_id = ?2",
                rusqlite::params![
                    3_u64.to_be_bytes().to_vec(),
                    request.recording_id.as_uuid().as_bytes().to_vec()
                ],
            )
            .expect("damage sequence continuity");
        let discontinuous = reader
            .show_recording(&request_for(project.id()))
            .expect_err("discontinuous stored range rejected");
        assert_eq!(discontinuous.kind(), PortErrorKind::Corruption);
        connection
            .execute(
                "UPDATE recording_segments SET first_recording_seq = ?1, last_recording_seq = ?2 \
                 WHERE recording_id = ?3",
                rusqlite::params![
                    2_u64.to_be_bytes().to_vec(),
                    2_u64.to_be_bytes().to_vec(),
                    request.recording_id.as_uuid().as_bytes().to_vec()
                ],
            )
            .expect("restore sequence metadata");
        connection
            .execute(
                "UPDATE recording_segments SET uncompressed_bytes = uncompressed_bytes + 1 \
                 WHERE recording_id = ?1",
                rusqlite::params![request.recording_id.as_uuid().as_bytes().to_vec()],
            )
            .expect("tamper logical size metadata");
        let size_mismatch = reader
            .show_recording(&request_for(project.id()))
            .expect_err("uncompressed-size metadata must match the verified stream");
        assert_eq!(size_mismatch.kind(), PortErrorKind::Corruption);
        connection
            .execute(
                "UPDATE recording_segments SET uncompressed_bytes = ?1 \
                 WHERE recording_id = ?2",
                rusqlite::params![
                    i64::try_from(receipt.uncompressed_bytes).expect("uncompressed size"),
                    request.recording_id.as_uuid().as_bytes().to_vec()
                ],
            )
            .expect("restore logical size metadata");

        let object_path = {
            let text = receipt.object_hash.to_canonical();
            let digest = text.strip_prefix("b3:").expect("canonical hash");
            directory
                .path()
                .join("objects/b3")
                .join(&digest[..2])
                .join(format!("{}.xtf.zst", &digest[2..]))
        };
        let valid = std::fs::read(&object_path).expect("object file");
        std::fs::write(&object_path, b"malformed XTF").expect("corrupt object");
        let corrupt = reader
            .show_recording(&request_for(project.id()))
            .expect_err("malformed stored XTF rejected");
        assert_eq!(corrupt.kind(), PortErrorKind::Corruption);
        std::fs::write(&object_path, valid).expect("restore verified fixture object");
        std::fs::remove_file(&object_path).expect("remove object");
        let missing =
            reader.show_recording(&request_for(project.id())).expect_err("missing object rejected");
        assert_eq!(missing.kind(), PortErrorKind::Corruption);
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
        capture.begin_recording(begin.clone()).expect("begin");

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
            .finish_recording(FinishRecording::without_digest(begin.recording_id, 3))
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
    fn capture_beyond_event_capacity_ends_partial_with_durable_drop_count() {
        // Intended contract change (owner-ordered F5): exceeding the event
        // capacity no longer kills the capture with a Resource error.
        use xtrace_application::recording::MAX_RECORDED_EVENTS;
        let (directory, store, project) = fixture();
        let adapter =
            std::sync::Arc::new(SqliteRecordingPersistence::new(store.clone(), directory.path()));
        let capture = RecordingCaptureService::new(
            std::sync::Arc::clone(&adapter),
            SegmentPolicy::default(),
            std::num::NonZeroUsize::new(2).expect("non-zero recording limit"),
        );
        let begin = begin(project.id(), RecordingId::new());
        let recording_id = begin.recording_id;
        capture.begin_recording(begin).expect("begin");
        let last_kept = 1 + MAX_RECORDED_EVENTS as u64;
        let extra = 7_u64;
        let events = (2..=last_kept + extra)
            .map(|sequence| {
                let priority = if sequence > last_kept { 5 + (sequence % 2) as u32 } else { 1 };
                event_with_priority(sequence, &format!("event-{sequence}"), priority)
            })
            .collect::<Vec<_>>();
        let mut accepted = 0;
        let mut dropped = 0;
        for chunk in events.chunks(512) {
            let receipt = capture
                .record_events(RecordEvents { recording_id, events: chunk.to_vec() })
                .expect("capture survives the capacity");
            accepted += receipt.accepted;
            dropped += receipt.dropped;
        }
        assert_eq!((accepted, dropped), (MAX_RECORDED_EVENTS, 7));

        let finish = FinishRecording {
            recording_id,
            final_recording_seq: last_kept + extra,
            duration_ns: None,
            // The adapter digest covers dropped events too; it cannot verify.
            event_digest: vec![9; 32],
            drop_counts_by_priority: [(6, 2)].into_iter().collect(),
            unsupported_capability_codes: Vec::new(),
            capacity_dropped_events: 0,
            event_cap: 2_048,
            outcome: None,
            response_summary: None,
        };
        let receipt = capture.finish_recording(finish.clone()).expect("finish");
        assert_eq!(receipt.completion, RecordingCompletion::Partial);
        let replay = capture.finish_recording(finish).expect("exact finish replay");
        assert!(replay.exact_replay);
        assert_eq!(replay.completion, RecordingCompletion::Partial);

        let stored_count: i64 = store
            .lock()
            .expect("metadata connection")
            .query_row(
                "SELECT event_count FROM recording_terminal_evidence WHERE recording_id = ?1",
                rusqlite::params![recording_id.as_uuid().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .expect("terminal evidence row");
        assert_eq!(stored_count, i64::try_from(MAX_RECORDED_EVENTS).expect("cap fits"));
        let stored_request: String = store
            .lock()
            .expect("metadata connection")
            .query_row(
                "SELECT request_json FROM recording_terminal_evidence WHERE recording_id = ?1",
                rusqlite::params![recording_id.as_uuid().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .expect("terminal evidence request");
        assert!(stored_request.contains("\"capacity_dropped_events\":7"), "{stored_request}");

        // Reopen through a fresh reader: persisted events verify and the drop
        // is visible, never Complete.
        let reader = SqliteRecordingReader::new(store, directory.path());
        let window = reader
            .show_recording(&ShowWindowRequest {
                project_id: project.id(),
                recording_id,
                limit: 1_000,
                after_sequence: None,
            })
            .expect("read capped capture");
        assert_eq!(
            window.completion,
            xtrace_application::recording_queries::RecordingCompletionEvidence::Partial
        );
        assert!(!window.events.is_empty());
        // Dropped sequences 2050..=2056: priority 5 for even, 6 for odd
        // sequences (3 + 4); the adapter's own 2 at priority 6 are added to 4.
        assert_eq!(window.drop_counts_by_priority.get(&5).map(String::as_str), Some("4"));
        assert_eq!(window.drop_counts_by_priority.get(&6).map(String::as_str), Some("5"));
        assert_eq!(window.drop_counts_by_priority.len(), 2);
        let last_window = reader
            .show_recording(&ShowWindowRequest {
                project_id: project.id(),
                recording_id,
                limit: 1_000,
                after_sequence: Some(last_kept - 3),
            })
            .expect("read capped capture tail");
        let tail =
            last_window.events.iter().map(|event| event.sequence.clone()).collect::<Vec<_>>();
        assert_eq!(tail, [last_kept - 2, last_kept - 1, last_kept].map(|s| s.to_string()));
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
        capture.begin_recording(begin.clone()).expect("begin");

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
            .finish_recording(FinishRecording::without_digest(begin.recording_id, 2))
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
        // An absent root cannot be admitted as private storage; the failure is the sanitized
        // private-storage error and exposes neither the path nor an OS error.
        assert_eq!(error.kind(), PortErrorKind::Validation);
        assert!(error.message().starts_with("XTR-PRIVATE-STORAGE-UNAVAILABLE"));
        assert_eq!(error.source(), None);
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

    // ---- Replay navigation over the v8 frame index (CONTRACTS 6.2, 8.3) ----

    use xtrace_application::recording_queries::{
        FrameNavigation, NavigationResult as Nav, NavigationUnavailable as Unav,
    };

    const K_REQUEST_UPDATE: i32 = 1;
    const K_ENTER: i32 = 2;
    const K_EXIT: i32 = 3;

    fn node(
        sequence: u64,
        event_id: &str,
        parent: &str,
        kind: i32,
    ) -> AcceptedRecordingEvent<XtfEventEnvelope> {
        let mut accepted = event(sequence, event_id);
        let nested = accepted.payload.event.as_mut().expect("typed payload");
        nested.parent_event_id = parent.to_owned();
        nested.kind = kind;
        accepted.canonical_bytes = accepted.payload.encode_to_vec();
        accepted
    }

    /// The tree used by the vector tests (sequence: id, parent, kind -> depth).
    ///
    /// ```text
    ///  2 root enter       d0     8 b-exit      d2
    ///  3 a enter          d1     9 root-exit   d1
    ///  4 a1 enter         d2    10 ghost enter d0 (parent never observed)
    ///  5 a1 exit          d3    11 request_update (not a frame)
    ///  6 a exit           d2
    ///  7 b enter          d1
    /// ```
    fn tree() -> Vec<AcceptedRecordingEvent<XtfEventEnvelope>> {
        vec![
            node(2, "root", "", K_ENTER),
            node(3, "a", "root", K_ENTER),
            node(4, "a1", "a", K_ENTER),
            node(5, "a1x", "a1", K_EXIT),
            node(6, "ax", "a", K_EXIT),
            node(7, "b", "root", K_ENTER),
            node(8, "bx", "b", K_EXIT),
            node(9, "rootx", "root", K_EXIT),
            node(10, "ghost", "never-observed", K_ENTER),
            node(11, "upd", "", K_REQUEST_UPDATE),
        ]
    }

    fn digest_of(events: &[AcceptedRecordingEvent<XtfEventEnvelope>]) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        for accepted in events {
            hasher.update(accepted.payload.event.as_ref().expect("event").event_id.as_bytes());
        }
        hasher.finalize().as_bytes().to_vec()
    }

    struct Persisted {
        _directory: tempfile::TempDir,
        store: SqliteStore,
        project: Project,
        recording_id: RecordingId,
        root: std::path::PathBuf,
    }

    /// Persists `events` in segments of `per_segment` and optionally finishes the
    /// recording as complete.
    fn persist(
        events: &[AcceptedRecordingEvent<XtfEventEnvelope>],
        per_segment: usize,
        finish: bool,
    ) -> Persisted {
        let (directory, store, project) = fixture();
        let recording_id = RecordingId::new();
        let adapter = SqliteRecordingPersistence::new(store.clone(), directory.path());
        adapter.begin_recording(&begin(project.id(), recording_id)).expect("begin");
        for (ordinal, chunk) in events.chunks(per_segment).enumerate() {
            adapter
                .persist_segment(&PersistRecordingSegment {
                    project_id: project.id(),
                    recording_id,
                    segment_ordinal: u32::try_from(ordinal).expect("ordinal"),
                    events: chunk.to_vec(),
                })
                .expect("persist segment");
        }
        if finish {
            let last = events.last().map_or(1, |event| event.recording_seq);
            adapter
                .finish_recording(&FinishRecording {
                    recording_id,
                    final_recording_seq: last,
                    duration_ns: Some(1),
                    event_digest: digest_of(events),
                    drop_counts_by_priority: std::collections::BTreeMap::new(),
                    unsupported_capability_codes: Vec::new(),
                    capacity_dropped_events: 0,
                    event_cap: 2_048,
                    outcome: None,
                    response_summary: None,
                })
                .expect("finish");
        }
        let root = directory.path().to_path_buf();
        Persisted { _directory: directory, store, project, recording_id, root }
    }

    fn window(
        persisted: &Persisted,
        limit: u32,
        after: Option<u64>,
    ) -> xtrace_application::recording_queries::RecordingEventWindow {
        SqliteRecordingReader::new(persisted.store.clone(), &persisted.root)
            .show_recording(&ShowWindowRequest {
                project_id: persisted.project.id(),
                recording_id: persisted.recording_id,
                limit,
                after_sequence: after,
            })
            .expect("window")
    }

    fn frame_ids(
        window: &xtrace_application::recording_queries::RecordingEventWindow,
    ) -> std::collections::HashMap<u64, xtrace_domain::FrameId> {
        window
            .events
            .iter()
            .map(|event| (event.sequence.parse().expect("seq"), event.frame_id.expect("frame id")))
            .collect()
    }

    fn nav_of(
        window: &xtrace_application::recording_queries::RecordingEventWindow,
        sequence: u64,
    ) -> FrameNavigation {
        window
            .events
            .iter()
            .find(|event| event.sequence == sequence.to_string())
            .expect("event in window")
            .navigation
    }

    #[test]
    fn depth_and_parent_populated_for_nested_frames_and_orphan_is_a_flagged_root() {
        let persisted = persist(&tree(), 3, true);
        let window = window(&persisted, 50, None);
        let ids = frame_ids(&window);
        let depth: Vec<(u64, Option<u32>)> = window
            .events
            .iter()
            .map(|event| (event.sequence.parse().expect("seq"), event.depth))
            .collect();
        assert_eq!(
            depth,
            [
                (2, Some(0)),
                (3, Some(1)),
                (4, Some(2)),
                (5, Some(3)),
                (6, Some(2)),
                (7, Some(1)),
                (8, Some(2)),
                (9, Some(1)),
                (10, Some(0)),
                (11, Some(0)),
            ]
        );
        let by_seq = |sequence: u64| {
            window
                .events
                .iter()
                .find(|event| event.sequence == sequence.to_string())
                .expect("event")
        };
        assert_eq!(by_seq(4).parent_frame_id, Some(ids[&3]));
        assert_eq!(by_seq(2).parent_frame_id, None);
        // R3: a parent that was never observed is not invented.
        assert_eq!(by_seq(10).parent_frame_id, None);
        let connection = persisted.store.lock().expect("connection");
        let (flags, indexed): (i64, i64) = connection
            .query_row(
                "SELECT honesty_flags, indexed_v FROM recording_frame_index \
                 WHERE recording_id = ?1 AND recording_seq = ?2",
                rusqlite::params![
                    persisted.recording_id.as_uuid().as_bytes().to_vec(),
                    10_u64.to_be_bytes().as_slice()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("row");
        assert_eq!(indexed, 1);
        assert_eq!(flags & i64::from(xtrace_domain::honesty_flags::ORPHAN_PARENT), 64);
    }

    #[test]
    fn navigation_vectors_into_over_out_previous_next() {
        let persisted = persist(&tree(), 4, true);
        let window = window(&persisted, 50, None);
        let id = frame_ids(&window);
        let t = |sequence: u64| Nav::Target { frame_id: id[&sequence] };
        // (sequence, previous, next, into, over, out)
        let table: Vec<(u64, Nav, Nav, Nav, Nav, Nav)> = vec![
            // root: into = first non-closing child; over skips to the next depth<=0 frame
            (2, Nav::Boundary, t(3), t(3), t(10), Nav::Boundary),
            (3, t(2), t(4), t(4), t(7), t(10)),
            // a leaf call's only child is its exit, so `into` falls back to `next`
            (4, t(3), t(5), t(5), t(6), t(7)),
            (5, t(4), t(6), t(6), t(6), t(6)),
            (7, t(6), t(8), t(8), t(9), t(10)),
            (8, t(7), t(9), t(9), t(9), t(9)),
            // a frame whose parent was never observed
            (
                10,
                t(9),
                Nav::Boundary,
                Nav::Boundary,
                Nav::Boundary,
                Nav::unavailable(Unav::OrphanParent),
            ),
        ];
        for (sequence, previous, next, into, over, out) in table {
            let got = nav_of(&window, sequence);
            assert_eq!(got.previous, previous, "previous of {sequence}");
            assert_eq!(got.next, next, "next of {sequence}");
            assert_eq!(got.into, into, "into of {sequence}");
            assert_eq!(got.over, over, "over of {sequence}");
            assert_eq!(got.out, out, "out of {sequence}");
        }
    }

    #[test]
    fn request_update_is_not_navigable_and_previous_next_skip_it() {
        let persisted = persist(&tree(), 10, true);
        let window = window(&persisted, 50, None);
        let not_navigable = Nav::unavailable(Unav::NotNavigable);
        let update = nav_of(&window, 11);
        for edge in [update.previous, update.next, update.into, update.over, update.out] {
            assert_eq!(edge, not_navigable);
        }
        let id = frame_ids(&window);
        // `next` of the last real frame skips the trailing request_update and ends the stream.
        assert_eq!(nav_of(&window, 10).next, Nav::Boundary);
        assert_eq!(nav_of(&window, 10).previous, Nav::Target { frame_id: id[&9] });
    }

    #[test]
    fn unfinished_recording_never_reports_boundary_past_the_frontier() {
        let persisted = persist(&tree()[..4], 2, false);
        let window = window(&persisted, 50, None);
        let last = nav_of(&window, 5);
        let frontier = Nav::unavailable(Unav::PartialFrontier);
        assert_eq!(last.next, frontier);
        assert_eq!(last.over, frontier);
        assert_eq!(last.out, frontier);
        // an interior frame still resolves
        assert!(matches!(nav_of(&window, 3).next, Nav::Target { .. }));
    }

    #[test]
    fn frame_navigation_endpoint_matches_embedded_navigation_and_checks_ownership() {
        let persisted = persist(&tree(), 4, true);
        let window = window(&persisted, 50, None);
        let id = frame_ids(&window);
        let reader = SqliteRecordingReader::new(persisted.store.clone(), &persisted.root);
        for sequence in 2..=11_u64 {
            let view = reader
                .frame_navigation(persisted.project.id(), persisted.recording_id, id[&sequence])
                .expect("frame navigation");
            assert_eq!(view.frame_id, id[&sequence]);
            assert_eq!(view.sequence, sequence.to_string());
            assert_eq!(view.navigation, nav_of(&window, sequence), "seq {sequence}");
        }
        let depth_of_a1 = reader
            .frame_navigation(persisted.project.id(), persisted.recording_id, id[&4])
            .expect("a1");
        assert_eq!(depth_of_a1.depth, Some(2));
        assert_eq!(depth_of_a1.parent_frame_id, Some(id[&3]));
        // unknown frame, another recording's frame and another project all read as not found
        let other = persist(&tree()[..3], 3, false);
        let other_ids = frame_ids(&self::window(&other, 50, None));
        for (project, recording, frame) in [
            (persisted.project.id(), persisted.recording_id, xtrace_domain::FrameId::new()),
            (persisted.project.id(), persisted.recording_id, other_ids[&2]),
            (ProjectId::new(), persisted.recording_id, id[&2]),
        ] {
            let error = reader.frame_navigation(project, recording, frame).expect_err("not found");
            assert_eq!(error.kind(), PortErrorKind::NotFound);
        }
    }

    #[test]
    fn around_frame_window_is_centred_on_the_anchor() {
        use xtrace_application::recording_queries::{RecordingQueryService, ShowRecording};
        let persisted = persist(&tree(), 4, true);
        let ids = frame_ids(&window(&persisted, 50, None));
        let service = RecordingQueryService::new(SqliteRecordingReader::new(
            persisted.store.clone(),
            &persisted.root,
        ));
        let show = |around: Option<xtrace_domain::FrameId>, limit: u32| {
            service.show(
                ShowRecording {
                    project_id: persisted.project.id(),
                    recording_id: persisted.recording_id,
                    limit,
                    cursor: None,
                    around_frame: around,
                },
                CorrelationId::new(),
            )
        };
        let detail = show(Some(ids[&7]), 5).expect("around window");
        let sequences: Vec<&str> =
            detail.events.iter().map(|event| event.sequence.as_str()).collect();
        assert_eq!(sequences, ["5", "6", "7", "8", "9"]);
        assert_eq!(detail.anchor_frame_id, Some(ids[&7]));
        assert_eq!(detail.first_sequence.as_deref(), Some("5"));
        // clamped at the start of the recording
        let head = show(Some(ids[&2]), 4).expect("head window");
        assert_eq!(head.events.first().map(|event| event.sequence.as_str()), Some("2"));
        assert_eq!(head.anchor_frame_id, Some(ids[&2]));
        // a frame of another recording is not found
        let other = persist(&tree()[..3], 3, false);
        let foreign = frame_ids(&window(&other, 50, None))[&2];
        assert!(show(Some(foreign), 5).is_err());
    }

    #[test]
    fn depth_overflow_is_flagged_and_navigation_unavailable() {
        // a chain deeper than the indexed bound: depth saturates, never wraps
        let mut events = Vec::new();
        for sequence in 2..=4_103_u64 {
            let parent = if sequence == 2 { String::new() } else { format!("n{}", sequence - 1) };
            events.push(node(sequence, &format!("n{sequence}"), &parent, K_ENTER));
        }
        let persisted = persist(&events, 1_000, false);
        let connection = persisted.store.lock().expect("connection");
        let (max_depth, overflow): (i64, i64) = connection
            .query_row(
                "SELECT max(depth), count(*) FROM recording_frame_index \
                 WHERE recording_id = ?1 AND (honesty_flags & ?2) != 0",
                rusqlite::params![
                    persisted.recording_id.as_uuid().as_bytes().to_vec(),
                    i64::from(xtrace_domain::honesty_flags::DEPTH_OVERFLOW)
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("overflow rows");
        assert_eq!(max_depth, 4_096);
        // sequences 4_099.. are deeper than 4_096 (depth = sequence - 2)
        assert_eq!(overflow, 4_103 - 4_098);
        drop(connection);
        let tail = window(&persisted, 10, Some(4_100));
        let nav = nav_of(&tail, 4_103);
        assert_eq!(nav.into, Nav::unavailable(Unav::DepthOverflow));
        assert_eq!(nav.over, Nav::unavailable(Unav::DepthOverflow));
        assert_eq!(nav.out, Nav::unavailable(Unav::DepthOverflow));
    }

    #[test]
    fn rows_written_before_the_index_population_stay_legacy_unindexed() {
        let persisted = persist(&tree()[..3], 3, true);
        {
            let connection = persisted.store.lock().expect("connection");
            connection
                .execute("UPDATE recording_frame_index SET indexed_v = 0, depth = 0", [])
                .expect("simulate a v4..v6 row");
        }
        let window = window(&persisted, 50, None);
        let legacy = Nav::unavailable(Unav::LegacyUnindexed);
        let first = nav_of(&window, 2);
        assert_eq!((first.into, first.over, first.out), (legacy, legacy, legacy));
        assert!(matches!(first.next, Nav::Target { .. }), "previous/next keep working");
        assert_eq!(window.events[0].depth, None);
    }

    #[test]
    fn index_population_is_idempotent_on_segment_retry() {
        let (directory, store, project) = fixture();
        let recording_id = RecordingId::new();
        let adapter = SqliteRecordingPersistence::new(store.clone(), directory.path());
        adapter.begin_recording(&begin(project.id(), recording_id)).expect("begin");
        let segment = PersistRecordingSegment {
            project_id: project.id(),
            recording_id,
            segment_ordinal: 0,
            events: tree()[..4].to_vec(),
        };
        adapter.persist_segment(&segment).expect("first");
        let rows = |store: &SqliteStore| -> Vec<(Vec<u8>, i64, Option<Vec<u8>>)> {
            let connection = store.lock().expect("connection");
            let mut statement = connection
                .prepare(
                    "SELECT frame_id, depth, parent_seq FROM recording_frame_index \
                     ORDER BY recording_seq",
                )
                .expect("prepare");
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .expect("query")
                .map(|row| row.expect("row"))
                .collect()
        };
        let before = rows(&store);
        assert_eq!(before.len(), 4);
        adapter.persist_segment(&segment).expect("exact replay");
        assert_eq!(rows(&store), before, "a retried segment keeps the same frame ids and depths");
    }

    // ---- RC-1 fixer B: review majors F1, F2, F3, F5 ----

    /// Like `persist` but finishes with a chosen capacity drop count and outcome.
    fn persist_finished_with(
        events: &[AcceptedRecordingEvent<XtfEventEnvelope>],
        per_segment: usize,
        capacity_dropped_events: u64,
        outcome: Option<xtrace_domain::RecordingOutcome>,
    ) -> Persisted {
        let persisted = persist(events, per_segment, false);
        let adapter = SqliteRecordingPersistence::new(persisted.store.clone(), &persisted.root);
        let last = events.last().map_or(1, |event| event.recording_seq);
        adapter
            .finish_recording(&FinishRecording {
                recording_id: persisted.recording_id,
                final_recording_seq: last,
                duration_ns: Some(1),
                // the adapter digest covers dropped events too, so it is withheld
                event_digest: if capacity_dropped_events > 0 {
                    Vec::new()
                } else {
                    digest_of(events)
                },
                drop_counts_by_priority: if capacity_dropped_events > 0 {
                    [(5, capacity_dropped_events)].into_iter().collect()
                } else {
                    std::collections::BTreeMap::new()
                },
                unsupported_capability_codes: Vec::new(),
                capacity_dropped_events,
                // a recording that dropped at capacity must have filled it
                event_cap: if capacity_dropped_events > 0 {
                    u64::try_from(events.len()).expect("fits")
                } else {
                    u64::try_from(events.len()).expect("fits").max(2_048)
                },
                outcome,
                response_summary: None,
            })
            .expect("finish");
        persisted
    }

    fn gap_node(sequence: u64, event_id: &str) -> AcceptedRecordingEvent<XtfEventEnvelope> {
        use xtrace_protocol::generated::agent::{GapPayload, GapReason};
        let mut gap = node(sequence, event_id, "", 14);
        gap.payload.event.as_mut().expect("event").gap = Some(GapPayload {
            reason: GapReason::LineBudget as i32,
            count: 1,
            first_recording_seq: sequence,
            last_recording_seq: sequence,
        });
        gap.canonical_bytes = gap.payload.encode_to_vec();
        gap
    }

    fn gap_only_events() -> Vec<AcceptedRecordingEvent<XtfEventEnvelope>> {
        let mut events = tree()[..8].to_vec();
        events.push(gap_node(10, "gap"));
        events
    }

    #[test]
    fn next_on_gap_only_partial_is_boundary() {
        let persisted = persist_finished_with(&gap_only_events(), 4, 0, None);
        let window = window(&persisted, 50, None);
        // the digest was verified and nothing was dropped: the end is real
        assert_eq!(nav_of(&window, 10).next, Nav::Boundary);
    }

    #[test]
    fn partial_with_capacity_drops_never_reports_boundary_past_the_frontier() {
        let persisted = persist_finished_with(&gap_only_events(), 4, 3, None);
        let window = window(&persisted, 50, None);
        assert_eq!(nav_of(&window, 10).next, Nav::unavailable(Unav::PartialFrontier));
    }

    #[test]
    fn partial_whose_digest_was_never_verified_is_not_a_final_frontier() {
        use xtrace_application::recording_queries::RecordingCompletionEvidence as Evidence;
        let persisted = persist_finished_with(&gap_only_events(), 4, 0, None);
        let cid = CorrelationId::new();
        let check = || {
            let connection = persisted.store.lock().expect("connection");
            crate::recording_store::persisted_frontier_is_final(
                &connection,
                persisted.recording_id,
                Evidence::Partial,
                cid,
            )
            .expect("frontier decision")
        };
        assert!(check(), "a verified gap-only partial ends at its last frame");
        // verify_terminal_evidence answers Partial without hashing once the declared
        // segment bytes pass the verification bound; that digest proves nothing.
        let over_bound = i64::try_from(xtrace_application::MAX_RECORDING_FINISH_VERIFIED_BYTES)
            .expect("fits")
            + 1;
        persisted
            .store
            .lock()
            .expect("connection")
            .execute(
                "UPDATE recording_segments SET uncompressed_bytes = ?1 WHERE recording_id = ?2",
                rusqlite::params![over_bound, persisted.recording_id.as_uuid().as_bytes().to_vec()],
            )
            .expect("simulate an over-budget declaration");
        assert!(!check(), "an unverified digest must not prove the end of the recording");
    }

    #[test]
    fn finish_between_read_bound_and_finish_bound_still_verifies_complete() {
        use xtrace_protocol::generated::agent::{
            BindingRole, CapturedValue as Wire, CapturedValueTruncated, NameOrigin, ValueBinding,
            captured_value::Value as V,
        };
        // Incompressible-ish payloads so that declared logical + compressed bytes pass the
        // 16 MiB verification bound: the recording is sealed Partial WITHOUT hashing, and the
        // read surface must name that cause (never a silent Partial).
        let heavy = |sequence: u64| {
            let mut accepted = node(sequence, &format!("h{sequence}"), "", K_ENTER);
            accepted.payload.event.as_mut().expect("event").bindings = (0..8_u32)
                .map(|index| {
                    let mut raw = [0_u8; 250];
                    blake3::Hasher::new()
                        .update(&sequence.to_le_bytes())
                        .update(&index.to_le_bytes())
                        .finalize_xof()
                        .fill(&mut raw);
                    let preview: String = raw.iter().map(|byte| format!("{byte:02x}")).collect();
                    ValueBinding {
                        name: format!("arg{index}"),
                        role: BindingRole::Argument as i32,
                        name_origin: NameOrigin::Declared as i32,
                        value: Some(Wire {
                            value: Some(V::Truncated(CapturedValueTruncated {
                                preview,
                                original_size_lower_bound: 9_000,
                                limit: 500,
                            })),
                        }),
                    }
                })
                .collect();
            accepted.canonical_bytes = accepted.payload.encode_to_vec();
            accepted
        };
        let events: Vec<_> = (2..=3_001_u64).map(heavy).collect();
        let persisted = persist_finished_with(&events, 100, 0, None);
        let window = window(&persisted, 10, None);
        // Declared bytes pass the 16 MiB WINDOW bound but sit far under the 512 MiB finish
        // bound, so the finish verified the digest and the recording is Complete.
        assert!(
            !window
                .incomplete_evidence
                .iter()
                .any(|reason| reason == "verification_budget_exceeded"),
            "{:?}",
            window.incomplete_evidence
        );
        let status: String = persisted
            .store
            .lock()
            .expect("connection")
            .query_row(
                "SELECT status FROM recordings WHERE recording_id = ?1",
                rusqlite::params![persisted.recording_id.as_uuid().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .expect("status");
        assert_eq!(status, "complete");
        // a normal complete recording carries no such reason
        let small = persist(&tree(), 4, true);
        assert!(
            !window_reasons(&small).iter().any(|reason| reason == "verification_budget_exceeded")
        );
    }

    #[test]
    fn finish_over_finish_bound_is_partial_with_reason() {
        let events = tree();
        let persisted = persist(&events, 4, false);
        // Declare more segment bytes than the 512 MiB finish bound before the finish arrives.
        let over_bound = i64::try_from(xtrace_application::MAX_RECORDING_FINISH_VERIFIED_BYTES)
            .expect("fits")
            + 1;
        persisted
            .store
            .lock()
            .expect("connection")
            .execute(
                "UPDATE recording_segments SET uncompressed_bytes = ?1 WHERE recording_id = ?2",
                rusqlite::params![over_bound, persisted.recording_id.as_uuid().as_bytes().to_vec()],
            )
            .expect("simulate an over-bound declaration");
        let adapter = SqliteRecordingPersistence::new(persisted.store.clone(), &persisted.root);
        let last = events.last().map_or(1, |event| event.recording_seq);
        let completion = adapter
            .finish_recording(&FinishRecording {
                recording_id: persisted.recording_id,
                final_recording_seq: last,
                duration_ns: Some(1),
                event_digest: digest_of(&events),
                drop_counts_by_priority: std::collections::BTreeMap::new(),
                unsupported_capability_codes: Vec::new(),
                capacity_dropped_events: 0,
                event_cap: 2_048,
                outcome: None,
                response_summary: None,
            })
            .expect("finish");
        assert_eq!(completion, RecordingCompletion::Partial);
        // The read surface names the cause from this same predicate (see the
        // `verification_budget_exceeded` reason in `show_recording`); a real 512 MiB recording
        // is not materialised in a unit test, and a window read of the forged row would
        // (rightly) fail segment verification.
        let within = {
            let connection = persisted.store.lock().expect("connection");
            crate::recording_store::declared_bytes_within_verification_bound(
                &connection,
                persisted.recording_id,
                CorrelationId::new(),
            )
            .expect("bound decision")
        };
        assert!(!within, "declared bytes past the finish bound must be reported as over budget");
    }

    fn window_reasons(persisted: &Persisted) -> Vec<String> {
        window(persisted, 50, None).incomplete_evidence
    }

    #[test]
    fn invalid_or_unavailable_completion_is_never_a_final_frontier() {
        use xtrace_application::recording_queries::RecordingCompletionEvidence as Evidence;
        let persisted = persist_finished_with(&gap_only_events(), 4, 0, None);
        let connection = persisted.store.lock().expect("connection");
        for completion in [Evidence::Invalid, Evidence::Unavailable] {
            assert!(
                !crate::recording_store::persisted_frontier_is_final(
                    &connection,
                    persisted.recording_id,
                    completion,
                    CorrelationId::new(),
                )
                .expect("decision"),
                "{completion:?}"
            );
        }
    }

    fn async_node(
        sequence: u64,
        event_id: &str,
        async_parent: &str,
    ) -> AcceptedRecordingEvent<XtfEventEnvelope> {
        let mut accepted = node(sequence, event_id, "", K_ENTER);
        accepted.payload.event.as_mut().expect("event").async_parent_event_id =
            async_parent.to_owned();
        accepted.canonical_bytes = accepted.payload.encode_to_vec();
        accepted
    }

    #[test]
    fn over_not_fooled_by_interleaved_async_root() {
        // root(2) > a(3) ; an async root(4) interleaved ; a-exit(5) ; root-exit(6)
        let events = vec![
            node(2, "root", "", K_ENTER),
            node(3, "a", "root", K_ENTER),
            async_node(4, "async-root", "a"),
            node(5, "ax", "a", K_EXIT),
            node(6, "rootx", "root", K_EXIT),
        ];
        let persisted = persist_finished_with(&events, 5, 0, None);
        let window = window(&persisted, 50, None);
        let id = frame_ids(&window);
        let async_root = Nav::Target { frame_id: id[&4] };
        let a = nav_of(&window, 3);
        // an async root is depth 0 and would satisfy `depth <= current` for every frame
        assert_ne!(a.over, async_root, "over landed on an async root");
        assert_eq!(a.over, Nav::Target { frame_id: id[&6] });
        assert_ne!(nav_of(&window, 2).over, async_root);
        assert_ne!(a.out, async_root, "out landed on an async root");
        assert_ne!(nav_of(&window, 5).out, async_root);
    }

    #[test]
    fn around_window_trim_keeps_anchor() {
        use xtrace_application::recording_queries::{RecordingQueryService, ShowRecording};
        use xtrace_protocol::generated::agent::{
            BindingRole, CapturedValue as Wire, CapturedValueTruncated, NameOrigin, ValueBinding,
            captured_value::Value as V,
        };
        // 300 fat frames (several KiB of projected bindings each): a 200-event window
        // cannot fit the 256 KiB projection budget, so the page must be trimmed.
        let fat = |sequence: u64| {
            let mut accepted = node(sequence, &format!("e{sequence}"), "", K_ENTER);
            accepted.payload.event.as_mut().expect("event").bindings = (0..8)
                .map(|index| ValueBinding {
                    name: format!("arg{index}"),
                    role: BindingRole::Argument as i32,
                    name_origin: NameOrigin::Declared as i32,
                    value: Some(Wire {
                        value: Some(V::Truncated(CapturedValueTruncated {
                            preview: "p".repeat(500),
                            original_size_lower_bound: 9_000,
                            limit: 500,
                        })),
                    }),
                })
                .collect();
            accepted.canonical_bytes = accepted.payload.encode_to_vec();
            accepted
        };
        let events: Vec<_> = (2..=301_u64).map(fat).collect();
        let persisted = persist_finished_with(&events, 100, 0, None);
        let anchor = frame_ids(&window(&persisted, 20, Some(145)))[&151];
        let service = RecordingQueryService::new(SqliteRecordingReader::new(
            persisted.store.clone(),
            &persisted.root,
        ));
        let detail = service
            .show(
                ShowRecording {
                    project_id: persisted.project.id(),
                    recording_id: persisted.recording_id,
                    limit: 200,
                    cursor: None,
                    around_frame: Some(anchor),
                },
                CorrelationId::new(),
            )
            .expect("around window");
        assert!(detail.events.len() < 200, "the byte budget must actually trim this page");
        assert_eq!(detail.anchor_frame_id, Some(anchor));
        assert!(
            detail.events.iter().any(|event| event.frame_id == Some(anchor)),
            "anchorFrameId must name a frame that is in the page"
        );
    }

    #[test]
    fn outcome_persists_and_reopens_and_unset_reads_unobserved() {
        use xtrace_domain::{OutcomeException, OutcomeKind, RecordingOutcome};
        let events = tree()[..8].to_vec();
        let responded = RecordingOutcome {
            kind: OutcomeKind::Responded,
            http_status: Some(201),
            exception: None,
            thrown_from_event_id: None,
        };
        let persisted = persist_finished_with(&events, 4, 0, Some(responded));
        let outcome = window(&persisted, 50, None).outcome.expect("terminal evidence present");
        assert_eq!(
            (outcome.kind.as_str(), outcome.http_status, outcome.exception.is_none()),
            ("responded", Some(201), true)
        );

        let thrown = RecordingOutcome {
            kind: OutcomeKind::ExceptionPropagated,
            http_status: Some(500),
            exception: Some(OutcomeException {
                exception_type: "IllegalStateException".to_owned(),
                message: "boom".to_owned(),
            }),
            thrown_from_event_id: Some("a1".to_owned()),
        };
        let persisted = persist_finished_with(&events, 4, 0, Some(thrown));
        let outcome = window(&persisted, 50, None).outcome.expect("outcome");
        assert_eq!(outcome.kind, "exception_propagated");
        let exception = outcome.exception.expect("exception");
        assert_eq!(
            (exception.exception_type.as_str(), exception.message.as_deref()),
            ("IllegalStateException", Some("boom"))
        );
        assert_eq!(outcome.thrown_from_event_id.as_deref(), Some("a1"));

        // an adapter that observed nothing is never defaulted to `responded`
        let persisted = persist_finished_with(&events, 4, 0, None);
        let outcome = window(&persisted, 50, None).outcome.expect("outcome");
        assert_eq!((outcome.kind.as_str(), outcome.http_status), ("unobserved", None));
        // no terminal evidence at all reads null
        let unfinished = persist(&events, 4, false);
        assert!(window(&unfinished, 50, None).outcome.is_none());
    }

    #[test]
    fn frame_honesty_counts_are_exact_and_unavailable_for_legacy_frames() {
        let persisted = persist(&tree(), 4, true);
        let counts = window(&persisted, 50, None).frame_honesty.expect("indexed counts");
        assert_eq!(counts.orphan_parent, 1, "only the ghost frame has an unobserved parent");
        assert_eq!(
            (counts.gap, counts.redacted, counts.truncated, counts.unavailable, counts.dropped),
            (0, 0, 0, 0, 0)
        );
        let with_gap = persist_finished_with(&gap_only_events(), 4, 0, None);
        assert_eq!(window(&with_gap, 50, None).frame_honesty.expect("counts").gap, 1);
        persisted
            .store
            .lock()
            .expect("connection")
            .execute(
                "UPDATE recording_frame_index SET indexed_v = 0, depth = 0 WHERE recording_seq = ?1",
                rusqlite::params![3_u64.to_be_bytes().as_slice()],
            )
            .expect("make one frame legacy");
        assert!(
            window(&persisted, 50, None).frame_honesty.is_none(),
            "counts are unavailable, never zero-filled, once any frame predates the index"
        );
    }

    #[test]
    fn bindings_gap_and_line_are_projected_from_stored_events() {
        use xtrace_protocol::generated::agent::{
            BindingRole, CapturedValue as Wire, CapturedValueCaptured, CapturedValueDropped,
            CapturedValueRedacted, CapturedValueTruncated, CapturedValueUnavailable, GapPayload,
            GapReason, NameOrigin, ValueBinding, ValueShape as WireShape,
            captured_value::Value as V,
        };
        let binding = |name: &str, value: V| ValueBinding {
            name: name.to_owned(),
            role: BindingRole::Argument as i32,
            name_origin: NameOrigin::Declared as i32,
            value: Some(Wire { value: Some(value) }),
        };
        let mut enter = node(2, "m", "", K_ENTER);
        {
            let nested = enter.payload.event.as_mut().expect("event");
            nested.bindings = vec![
                binding(
                    "id",
                    V::Captured(CapturedValueCaptured {
                        shape: WireShape::Integer64 as i32,
                        preview: "42".to_owned(),
                        content_hash: blake3::hash(b"42").as_bytes().to_vec().into(),
                    }),
                ),
                binding(
                    "secret",
                    V::Redacted(CapturedValueRedacted {
                        rule_id: "name-secret".to_owned(),
                        shape_hint: WireShape::String as i32,
                    }),
                ),
                binding(
                    "body",
                    V::Truncated(CapturedValueTruncated {
                        preview: "abc".to_owned(),
                        original_size_lower_bound: 900,
                        limit: 3,
                    }),
                ),
                binding("x", V::Unavailable(CapturedValueUnavailable { reason: 7 })),
                binding("y", V::Dropped(CapturedValueDropped { reason: 2 })),
            ];
            // method extent only: a frame event must never report a line
            nested.source_binding =
                xtrace_protocol::generated::agent::SourceBinding::ObservedUnattested as i32;
            nested.source = Some(xtrace_protocol::generated::agent::SourceRange {
                path: "src/A.java".to_owned(),
                start_line: 10,
                end_line: 20,
                content_hash: vec![7; 32].into(),
                ..Default::default()
            });
        }
        enter.canonical_bytes = enter.payload.encode_to_vec();
        let mut line = node(3, "l", "m", 5);
        {
            let nested = line.payload.event.as_mut().expect("event");
            nested.source_binding =
                xtrace_protocol::generated::agent::SourceBinding::ObservedUnattested as i32;
            nested.source = Some(xtrace_protocol::generated::agent::SourceRange {
                path: "src/A.java".to_owned(),
                start_line: 14,
                end_line: 14,
                content_hash: vec![7; 32].into(),
                ..Default::default()
            });
        }
        line.canonical_bytes = line.payload.encode_to_vec();
        let mut gap = node(4, "g", "m", 14);
        {
            let nested = gap.payload.event.as_mut().expect("event");
            nested.gap = Some(GapPayload {
                reason: GapReason::LineBudget as i32,
                count: 9,
                first_recording_seq: 3,
                last_recording_seq: 3,
            });
        }
        gap.canonical_bytes = gap.payload.encode_to_vec();
        let persisted = persist(&[enter, line, gap], 3, false);
        let window = window(&persisted, 10, None);
        let enter = &window.events[0];
        assert_eq!(enter.line, None, "R4: a method extent is not an active line");
        let states: Vec<&str> = enter
            .bindings
            .iter()
            .map(|binding| match binding.value {
                xtrace_application::PersistedValue::Captured { .. } => "captured",
                xtrace_application::PersistedValue::Redacted { .. } => "redacted",
                xtrace_application::PersistedValue::Truncated { .. } => "truncated",
                xtrace_application::PersistedValue::Unavailable { .. } => "unavailable",
                xtrace_application::PersistedValue::Dropped { .. } => "dropped",
            })
            .collect();
        assert_eq!(states, ["captured", "redacted", "truncated", "unavailable", "dropped"]);
        assert_eq!(enter.bindings[0].role, "argument");
        assert_eq!(enter.bindings[0].name_origin, "declared");
        assert!(matches!(
            &enter.bindings[0].value,
            xtrace_application::PersistedValue::Captured { shape, preview, content_hash }
                if shape == "integer" && preview == "42"
                    && *content_hash == ContentHash::of_bytes(b"42").to_canonical()
        ));
        assert!(matches!(
            &enter.bindings[1].value,
            xtrace_application::PersistedValue::Redacted { rule_id, shape_hint }
                if rule_id == "name-secret" && shape_hint.as_deref() == Some("string")
        ));
        assert_eq!(window.events[1].line, Some(14));
        assert!(window.events[1].bindings.is_empty());
        let gap = window.events[2].gap.as_ref().expect("gap payload");
        assert_eq!(
            (gap.reason.as_str(), gap.count.as_str(), gap.first_sequence.as_str()),
            ("line_budget", "9", "3")
        );
        // honesty bits: values + redacted + truncated + unavailable + dropped on the enter frame, gap on the gap frame
        let connection = persisted.store.lock().expect("connection");
        let flags = |sequence: u64| -> u32 {
            connection
                .query_row(
                    "SELECT honesty_flags FROM recording_frame_index \
                     WHERE recording_id = ?1 AND recording_seq = ?2",
                    rusqlite::params![
                        persisted.recording_id.as_uuid().as_bytes().to_vec(),
                        sequence.to_be_bytes().as_slice()
                    ],
                    |row| row.get(0),
                )
                .expect("flags")
        };
        use xtrace_domain::honesty_flags as f;
        assert_eq!(
            flags(2),
            f::HAS_VALUES
                | f::HAS_REDACTED
                | f::HAS_TRUNCATED
                | f::HAS_UNAVAILABLE
                | f::HAS_DROPPED
        );
        assert_eq!(flags(3), 0);
        assert_eq!(flags(4), f::HAS_GAP);
    }

    /// Upper bound on `/bin/ls` spawns for one steady-state `commit_segment` (ADR 0008
    /// Amendment 1). Measured at 70 with the scope on the leased Mac; a commit spawned about 327 before it.
    const COMMIT_SPAWN_BOUND: u64 = 85;
    /// Bounds for `begin_recording` (measured 9, 32 unscoped) and `finish_recording` (measured 52, 277 unscoped).
    const BEGIN_SPAWN_BOUND: u64 = 20;
    const FINISH_SPAWN_BOUND: u64 = 100;

    // Signal only on macOS: the Linux admission path spawns nothing, so every count is 0 there by design.
    #[test]
    fn a_steady_state_commit_segment_stays_within_the_admission_spawn_bound() {
        use xtrace_private_storage::spawn_counter::ls_spawns_on_this_thread as spawns;
        let (directory, store, project) = fixture();
        let recording_id = RecordingId::new();
        let adapter = SqliteRecordingPersistence::new(store, directory.path());
        let before = spawns();
        adapter.begin_recording(&begin(project.id(), recording_id)).expect("begin recording");
        let begin_spawns = spawns() - before;
        let mut digest_input = String::new();
        let mut commits = Vec::new();
        for ordinal in 0_u32..6 {
            let sequence = u64::from(ordinal) + 2;
            let name = format!("event-{sequence}");
            digest_input.push_str(&name);
            let segment = PersistRecordingSegment {
                project_id: project.id(),
                recording_id,
                segment_ordinal: ordinal,
                events: vec![event(sequence, &name)],
            };
            let before = spawns();
            adapter.persist_segment(&segment).expect("persist segment");
            commits.push(spawns() - before);
        }
        let finish = FinishRecording {
            recording_id,
            final_recording_seq: 7,
            duration_ns: Some(77),
            event_digest: blake3::hash(digest_input.as_bytes()).as_bytes().to_vec(),
            drop_counts_by_priority: [(1, 0)].into_iter().collect(),
            unsupported_capability_codes: Vec::new(),
            capacity_dropped_events: 0,
            event_cap: 2_048,
            outcome: None,
            response_summary: None,
        };
        let before = spawns();
        adapter.finish_recording(&finish).expect("finish recording");
        let finish_spawns = spawns() - before;
        println!(
            "SPAWNS begin={begin_spawns} commits={commits:?} finish={finish_spawns} bound={COMMIT_SPAWN_BOUND}"
        );
        if cfg!(target_os = "macos") {
            assert!(commits.iter().all(|count| *count > 0), "the macOS probe must be counted");
            assert!(begin_spawns > 0 && finish_spawns > 0, "the macOS probe must be counted");
        }
        assert!(
            begin_spawns <= BEGIN_SPAWN_BOUND,
            "begin spawned {begin_spawns} probes, bound {BEGIN_SPAWN_BOUND}"
        );
        assert!(
            finish_spawns <= FINISH_SPAWN_BOUND,
            "finish spawned {finish_spawns} probes, bound {FINISH_SPAWN_BOUND}"
        );
        // Commit 0 creates the recording's staging directories; the rest are steady state.
        for (ordinal, count) in commits.iter().enumerate().skip(1) {
            assert!(
                *count <= COMMIT_SPAWN_BOUND,
                "commit {ordinal} spawned {count} probes, bound {COMMIT_SPAWN_BOUND}"
            );
        }
    }
}
