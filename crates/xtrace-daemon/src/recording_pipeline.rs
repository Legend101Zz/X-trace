//! Daemon-owned translation and blocking execution for recording capture.

use std::collections::BTreeMap;
use std::sync::Arc;

use prost::Message as _;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinError;
use uuid::Uuid;
use xtrace_application::PortError;
use xtrace_application::recording::{
    AcceptedRecordingEvent, BeginRecording, EndpointObservationInput, FinishRecording,
    RecordEvents, RecordingCapture,
};
use xtrace_domain::{
    CapturedValue, ProjectId, RecordingId, RuntimeSessionId, UnavailableReason, ValueShape,
    WallTime,
};
use xtrace_protocol::generated::agent::{EventBatch, RecordingFinished, RecordingStarted};
use xtrace_protocol::xtf::XtfEventEnvelope;

use crate::runtime::IncomingEnvelope;

const RECORDING_BLOCKING_CONCURRENCY: usize = 1;
/// Bounds active plus queued recording work across this daemon instance.
/// When all slots are occupied, the connection is rejected instead of adding
/// an unbounded waiter to the lane.
const RECORDING_SUBMISSION_SLOTS: usize = 64;

/// Executes recording operations on a daemon-scoped bounded blocking lane.
#[derive(Clone)]
pub(crate) struct RecordingPipeline {
    capture: Arc<dyn RecordingCapture<Event = XtfEventEnvelope>>,
    run_observation: EndpointObservationInput,
    lane: Arc<BlockingLane>,
}

impl RecordingPipeline {
    pub(crate) fn new(
        capture: Arc<dyn RecordingCapture<Event = XtfEventEnvelope>>,
        run_observation: EndpointObservationInput,
    ) -> Self {
        Self {
            capture,
            run_observation,
            lane: Arc::new(BlockingLane::new(
                RECORDING_BLOCKING_CONCURRENCY,
                RECORDING_SUBMISSION_SLOTS,
            )),
        }
    }

    pub(crate) async fn process(
        &self,
        incoming: IncomingEnvelope,
        project_id: ProjectId,
        runtime_session_id: RuntimeSessionId,
        shutdown: crate::daemon::ShutdownSignal,
    ) -> Result<(), RecordingPipelineError> {
        match incoming {
            IncomingEnvelope::CapabilitySet(_) | IncomingEnvelope::Health(_) => Ok(()),
            IncomingEnvelope::RecordingStarted(started) => {
                let request = translate_started(
                    &started,
                    project_id,
                    runtime_session_id,
                    &self.run_observation,
                )?;
                let capture = Arc::clone(&self.capture);
                let mode = effective_capture_mode(
                    xtrace_domain::CaptureMode::Standard,
                    &started.capture_policy_id,
                );
                self.lane
                    .run(shutdown, move || {
                        capture.begin_recording_with_mode(request, mode).map(|_| ())
                    })
                    .await
            }
            IncomingEnvelope::EventBatch(batch) => {
                let request = translate_batch(batch)?;
                let capture = Arc::clone(&self.capture);
                self.lane.run(shutdown, move || capture.record_events(request).map(|_| ())).await
            }
            IncomingEnvelope::RecordingFinished(finished) => {
                let request = translate_finished(&finished)?;
                let capture = Arc::clone(&self.capture);
                self.lane.run(shutdown, move || capture.finish_recording(request).map(|_| ())).await
            }
        }
    }
}

struct BlockingLane {
    permits: Arc<Semaphore>,
    submissions: Arc<Semaphore>,
}

/// Bounds the number of synchronous operations that can be active or waiting.
/// A queued wait observes shutdown; after `spawn_blocking` starts, its join
/// handle is always awaited because synchronous port work cannot be preempted.
/// Consequently, normal serve shutdown waits for started work to return; this
/// lane does not promise a wall-clock deadline for filesystem operations.
impl BlockingLane {
    fn new(concurrency: usize, submission_slots: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(concurrency)),
            submissions: Arc::new(Semaphore::new(submission_slots)),
        }
    }

    async fn run<F>(
        &self,
        mut shutdown: crate::daemon::ShutdownSignal,
        operation: F,
    ) -> Result<(), RecordingPipelineError>
    where
        F: FnOnce() -> Result<(), PortError> + Send + 'static,
    {
        let submission =
            Arc::clone(&self.submissions).try_acquire_owned().map_err(|error| match error {
                tokio::sync::TryAcquireError::NoPermits => RecordingPipelineError::QueueFull,
                tokio::sync::TryAcquireError::Closed => RecordingPipelineError::LaneClosed,
            })?;
        let permit = tokio::select! {
            biased;
            _ = shutdown.wait() => return Err(RecordingPipelineError::Cancelled),
            result = Arc::clone(&self.permits).acquire_owned() => {
                result.map_err(|_| RecordingPipelineError::LaneClosed)?
            }
        };
        run_blocking(permit, submission, operation).await
    }
}

async fn run_blocking<F>(
    permit: OwnedSemaphorePermit,
    submission: OwnedSemaphorePermit,
    operation: F,
) -> Result<(), RecordingPipelineError>
where
    F: FnOnce() -> Result<(), PortError> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _submission = submission;
        operation()
    })
    .await
    .map_err(RecordingPipelineError::Join)?
    .map_err(RecordingPipelineError::Port)
}

/// Effective capture mode of one recording (CONTRACTS 4.2): the lower of the session's armed
/// mode and the mode its claimed policy id names, so a focused claim on a session that was
/// never armed for focused capture stays standard. Ingest and the application layer both
/// take this value, so they apply the same cap.
///
/// Arming (the launch bootstrap's `capture.mode` and `ARM_FOCUSED_CAPTURE`) is not wired into
/// the session yet; the armed mode is always standard until it is.
pub(crate) fn effective_capture_mode(
    armed: xtrace_domain::CaptureMode,
    claimed_policy_id: &str,
) -> xtrace_domain::CaptureMode {
    use xtrace_domain::CaptureMode::{Focused, Standard};
    match (armed, xtrace_domain::CaptureMode::from_policy_id(claimed_policy_id)) {
        (Focused, Focused) => Focused,
        _ => Standard,
    }
}

fn translate_started(
    started: &RecordingStarted,
    project_id: ProjectId,
    runtime_session_id: RuntimeSessionId,
    run_observation: &EndpointObservationInput,
) -> Result<BeginRecording, RecordingPipelineError> {
    let mut endpoint_observation = run_observation.clone();
    endpoint_observation.method = started.method.clone();
    endpoint_observation.route_template = started.matched_route_template.clone();
    Ok(BeginRecording {
        project_id,
        recording_id: recording_id(&started.recording_id)?,
        runtime_session_id,
        opened_at: WallTime::now(),
        endpoint_observation,
    })
}

fn translate_batch(
    batch: EventBatch,
) -> Result<RecordEvents<XtfEventEnvelope>, RecordingPipelineError> {
    let recording_id = recording_id(&batch.recording_id)?;
    let events = batch
        .events
        .into_iter()
        .map(|event| {
            let recording_seq = event.recording_seq;
            let monotonic_ns = event.monotonic_ns;
            let priority = event.priority;
            let payload = XtfEventEnvelope { recording_seq, event: Some(event) };
            AcceptedRecordingEvent {
                recording_seq,
                monotonic_ns,
                priority,
                canonical_bytes: payload.encode_to_vec(),
                payload,
            }
        })
        .collect();
    Ok(RecordEvents { recording_id, events })
}

fn translate_finished(
    finished: &RecordingFinished,
) -> Result<FinishRecording, RecordingPipelineError> {
    Ok(FinishRecording {
        recording_id: recording_id(&finished.recording_id)?,
        final_recording_seq: finished.final_recording_seq,
        duration_ns: Some(finished.duration_ns),
        event_digest: finished.event_digest.to_vec(),
        drop_counts_by_priority: finished
            .drop_counts_by_priority
            .iter()
            .map(|(priority, count)| (*priority, *count))
            .collect::<BTreeMap<_, _>>(),
        unsupported_capability_codes: finished.unsupported_capability_codes.clone(),
        capacity_dropped_events: 0,
        event_cap: xtrace_application::legacy_event_cap(),
        response_summary: finished
            .response_summary
            .as_ref()
            .map(captured_value_from_wire)
            .transpose()?,
        outcome: finished
            .outcome
            .as_ref()
            .map(xtrace_protocol::translate::outcome_from_wire)
            .transpose()
            .map_err(|_| RecordingPipelineError::InvalidFinishEvidence)?,
    })
}

fn captured_value_from_wire(
    value: &xtrace_protocol::generated::agent::CapturedValue,
) -> Result<CapturedValue, RecordingPipelineError> {
    use xtrace_protocol::generated::agent::captured_value::Value as WireValue;
    let invalid = || RecordingPipelineError::InvalidFinishEvidence;
    match value.value.as_ref().ok_or_else(invalid)? {
        WireValue::Captured(_) => {
            Ok(CapturedValue::Unavailable { reason: UnavailableReason::PrivacyPolicyUnavailable })
        }
        WireValue::Redacted(redacted) => {
            if redacted.rule_id.is_empty() || redacted.rule_id.len() > 128 {
                return Err(invalid());
            }
            let shape_hint =
                (redacted.shape_hint != 0).then(|| value_shape(redacted.shape_hint)).flatten();
            if redacted.shape_hint != 0 && shape_hint.is_none() {
                return Err(invalid());
            }
            Ok(CapturedValue::Redacted {
                // The producer's free-form rule label has no manifest-backed
                // registry, so retain only the state and a fixed provenance.
                rule_id: "unverified-producer-redaction".to_string(),
                shape_hint,
            })
        }
        WireValue::Truncated(truncated) => {
            if truncated.limit == 0 {
                return Err(invalid());
            }
            Ok(CapturedValue::Unavailable { reason: UnavailableReason::PrivacyPolicyUnavailable })
        }
        WireValue::Unavailable(unavailable) => {
            let reason =
                xtrace_protocol::translate::unavailable_reason_from_wire(unavailable.reason)
                    .ok_or_else(invalid)?;
            Ok(CapturedValue::Unavailable { reason })
        }
        WireValue::Dropped(dropped) => {
            let reason = xtrace_protocol::translate::drop_reason_from_wire(dropped.reason)
                .ok_or_else(invalid)?;
            Ok(CapturedValue::Dropped { reason })
        }
    }
}

fn value_shape(shape: i32) -> Option<ValueShape> {
    Some(match shape {
        1 => ValueShape::String,
        2 => ValueShape::Boolean,
        3 => ValueShape::Integer { bits: 8 },
        4 => ValueShape::Integer { bits: 16 },
        5 => ValueShape::Integer { bits: 32 },
        6 => ValueShape::Integer { bits: 64 },
        7 => ValueShape::Float { bits: 32 },
        8 => ValueShape::Float { bits: 64 },
        9 => ValueShape::Null,
        10 => ValueShape::Bytes,
        // The wire enum carries no collection cardinality. Unknown is the
        // honest domain shape because length cannot be reconstructed.
        11..=13 => ValueShape::Unknown,
        _ => return None,
    })
}

fn recording_id(bytes: &[u8]) -> Result<RecordingId, RecordingPipelineError> {
    let bytes: &[u8; 16] =
        bytes.try_into().map_err(|_| RecordingPipelineError::InvalidRecordingId)?;
    Ok(RecordingId::from_uuid(Uuid::from_bytes(*bytes)))
}

#[derive(Debug)]
pub(crate) enum RecordingPipelineError {
    Port(PortError),
    Join(JoinError),
    LaneClosed,
    QueueFull,
    Cancelled,
    InvalidRecordingId,
    InvalidFinishEvidence,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "test fixture assertions")]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;

    use prost::Message as _;
    use tokio::sync::Semaphore;
    use xtrace_application::recording::{
        BeginRecording, BeginRecordingReceipt, EndpointObservationInput, FinishRecordingReceipt,
        RecordEvents, RecordEventsReceipt,
    };
    use xtrace_application::{PortError, PortErrorKind};
    use xtrace_domain::{CorrelationId, ProjectId, RecordingId, RuntimeSessionId, WallTime};
    use xtrace_protocol::generated::agent::{
        CapabilitySet, CapturedValue as WireCapturedValue, CapturedValueCaptured,
        CapturedValueRedacted, EventBatch, Health, RecordingEvent, RecordingFinished,
        RecordingStarted, ValueShape as WireValueShape, captured_value::Value as WireValue,
    };

    use super::{BlockingLane, RecordingPipeline, RecordingPipelineError, run_blocking};
    use crate::runtime::IncomingEnvelope;

    #[test]
    fn finish_summary_previews_and_rule_labels_never_cross_the_privacy_boundary() {
        let captured = WireCapturedValue {
            value: Some(WireValue::Captured(CapturedValueCaptured {
                shape: WireValueShape::String as i32,
                preview: "private-response-canary".to_string(),
                content_hash: prost::bytes::Bytes::from(vec![7; 32]),
            })),
        };
        assert!(matches!(
            super::captured_value_from_wire(&captured).expect("preview becomes unavailable"),
            xtrace_domain::CapturedValue::Unavailable {
                reason: xtrace_domain::UnavailableReason::PrivacyPolicyUnavailable
            }
        ));

        let redacted = WireCapturedValue {
            value: Some(WireValue::Redacted(CapturedValueRedacted {
                rule_id: "private-rule-canary".to_string(),
                shape_hint: WireValueShape::String as i32,
            })),
        };
        assert!(matches!(
            super::captured_value_from_wire(&redacted).expect("redaction is normalized"),
            xtrace_domain::CapturedValue::Redacted { rule_id, .. }
                if rule_id == "unverified-producer-redaction"
        ));
    }

    #[derive(Clone, Debug)]
    enum Operation {
        Started(BeginRecording),
        Events(RecordEvents<xtrace_protocol::xtf::XtfEventEnvelope>),
        Finished(xtrace_application::recording::FinishRecording),
    }

    #[derive(Default)]
    struct FakeCapture {
        operations: Mutex<Vec<Operation>>,
        fail_events: std::sync::atomic::AtomicBool,
    }

    impl xtrace_application::recording::RecordingCapture for FakeCapture {
        type Event = xtrace_protocol::xtf::XtfEventEnvelope;

        fn begin_recording(
            &self,
            request: BeginRecording,
        ) -> Result<BeginRecordingReceipt, PortError> {
            self.operations.lock().expect("operations").push(Operation::Started(request.clone()));
            Ok(BeginRecordingReceipt {
                recording_id: request.recording_id,
                disposition: xtrace_application::recording::BeginRecordingDisposition::Inserted,
            })
        }

        fn record_events(
            &self,
            request: RecordEvents<Self::Event>,
        ) -> Result<RecordEventsReceipt, PortError> {
            self.operations.lock().expect("operations").push(Operation::Events(request));
            if self.fail_events.swap(false, Ordering::SeqCst) {
                return Err(capture_error());
            }
            Ok(RecordEventsReceipt { accepted: 1, ..RecordEventsReceipt::default() })
        }

        fn finish_recording(
            &self,
            request: xtrace_application::recording::FinishRecording,
        ) -> Result<FinishRecordingReceipt, PortError> {
            let recording_id = request.recording_id;
            self.operations.lock().expect("operations").push(Operation::Finished(request));
            Ok(FinishRecordingReceipt {
                recording_id,
                persisted_segments: 0,
                exact_replay: false,
                completion: xtrace_application::recording::RecordingCompletion::Partial,
            })
        }
    }

    fn recording_id_bytes() -> prost::bytes::Bytes {
        prost::bytes::Bytes::copy_from_slice(&[0x45; 16])
    }

    fn capture_error() -> PortError {
        PortError::new(PortErrorKind::Internal, "expected test failure", CorrelationId::new())
    }

    #[tokio::test]
    #[allow(clippy::panic, reason = "operation variant assertions in this test")]
    async fn translates_start_all_events_and_finish_and_passes_duplicate_batches() {
        let capture = std::sync::Arc::new(FakeCapture::default());
        let pipeline = RecordingPipeline::new(capture.clone(), EndpointObservationInput::default());
        let project_id = ProjectId::new();
        let runtime_session_id = RuntimeSessionId::new();
        let recording_id = RecordingId::from_uuid(uuid::Uuid::from_bytes([0x45; 16]));
        let (_shutdown_tx, shutdown) = crate::daemon::shared_shutdown_channel();

        pipeline
            .process(
                IncomingEnvelope::CapabilitySet(CapabilitySet::default()),
                project_id,
                runtime_session_id,
                shutdown.clone(),
            )
            .await
            .expect("capability set no-op");
        pipeline
            .process(
                IncomingEnvelope::Health(Health::default()),
                project_id,
                runtime_session_id,
                shutdown.clone(),
            )
            .await
            .expect("health no-op");
        pipeline
            .process(
                IncomingEnvelope::RecordingStarted(RecordingStarted {
                    recording_id: recording_id_bytes(),
                    recording_seq: 1,
                    method: "GET".to_owned(),
                    ..RecordingStarted::default()
                }),
                project_id,
                runtime_session_id,
                shutdown.clone(),
            )
            .await
            .expect("start");
        let batch = EventBatch {
            recording_id: recording_id_bytes(),
            events: vec![
                RecordingEvent {
                    event_id: "one".to_owned(),
                    recording_seq: 2,
                    monotonic_ns: 10,
                    ..RecordingEvent::default()
                },
                RecordingEvent {
                    event_id: "two".to_owned(),
                    recording_seq: 3,
                    monotonic_ns: 20,
                    ..RecordingEvent::default()
                },
            ],
        };
        pipeline
            .process(
                IncomingEnvelope::EventBatch(batch.clone()),
                project_id,
                runtime_session_id,
                shutdown.clone(),
            )
            .await
            .expect("event batch");
        pipeline
            .process(
                IncomingEnvelope::EventBatch(batch),
                project_id,
                runtime_session_id,
                shutdown.clone(),
            )
            .await
            .expect("event retry remains passed through");
        pipeline
            .process(
                IncomingEnvelope::RecordingFinished(RecordingFinished {
                    recording_id: recording_id_bytes(),
                    final_recording_seq: 3,
                    duration_ns: 55,
                    event_digest: prost::bytes::Bytes::copy_from_slice(
                        blake3::hash(b"onetwo").as_bytes(),
                    ),
                    ..RecordingFinished::default()
                }),
                project_id,
                runtime_session_id,
                shutdown.clone(),
            )
            .await
            .expect("finish");

        let operations = capture.operations.lock().expect("operations");
        assert_eq!(operations.len(), 4);
        let Operation::Started(ref start) = operations[0] else {
            panic!("first operation must be start");
        };
        assert_eq!(start.project_id, project_id);
        assert_eq!(start.recording_id, recording_id);
        assert_eq!(start.runtime_session_id, runtime_session_id);
        assert!(start.opened_at <= WallTime::now());
        for operation in [&operations[1], &operations[2]] {
            let Operation::Events(request) = operation else {
                panic!("batch operation expected");
            };
            assert_eq!(request.recording_id, recording_id);
            assert_eq!(request.events.len(), 2);
            assert_eq!(request.events[0].payload.recording_seq, 2);
            assert_eq!(request.events[0].payload.event.as_ref().unwrap().event_id, "one");
            assert_eq!(request.events[1].payload.recording_seq, 3);
            assert_eq!(request.events[1].payload.event.as_ref().unwrap().event_id, "two");
            assert_eq!(
                request.events[0].canonical_bytes,
                request.events[0].payload.encode_to_vec()
            );
        }
        let Operation::Finished(finish) = &operations[3] else {
            panic!("last operation must be finish");
        };
        assert_eq!(finish.recording_id, recording_id);
        assert_eq!(finish.final_recording_seq, 3);
        assert_eq!(finish.duration_ns, Some(55));
        assert_eq!(finish.event_digest, blake3::hash(b"onetwo").as_bytes());
    }

    #[tokio::test]
    #[allow(clippy::panic, reason = "operation variant assertion in this test")]
    async fn passes_run_context_and_only_start_method_and_route_to_begin_recording() {
        let capture = std::sync::Arc::new(FakeCapture::default());
        let pipeline = RecordingPipeline::new(
            capture.clone(),
            EndpointObservationInput {
                policy_id: Some("spring-orders-v1".to_owned()),
                application_component: Some("spring-fixture".to_owned()),
                binding_key: Some("default".to_owned()),
                ..EndpointObservationInput::default()
            },
        );
        let project_id = ProjectId::new();
        let runtime_session_id = RuntimeSessionId::new();
        let (_shutdown_tx, shutdown) = crate::daemon::shared_shutdown_channel();
        pipeline
            .process(
                IncomingEnvelope::RecordingStarted(RecordingStarted {
                    recording_id: recording_id_bytes(),
                    recording_seq: 1,
                    method: "POST".to_owned(),
                    matched_route_template: "/orders".to_owned(),
                    url_shape: "/orders?private=canary".to_owned(),
                    ..RecordingStarted::default()
                }),
                project_id,
                runtime_session_id,
                shutdown,
            )
            .await
            .expect("start");
        let operations = capture.operations.lock().expect("operations");
        let Operation::Started(start) = &operations[0] else { panic!("start is submitted") };
        assert_eq!(start.endpoint_observation.policy_id.as_deref(), Some("spring-orders-v1"));
        assert_eq!(
            start.endpoint_observation.application_component.as_deref(),
            Some("spring-fixture")
        );
        assert_eq!(start.endpoint_observation.binding_key.as_deref(), Some("default"));
        assert_eq!(start.endpoint_observation.method, "POST");
        assert_eq!(start.endpoint_observation.route_template, "/orders");
        assert!(!format!("{:?}", start.endpoint_observation).contains("canary"));
    }

    #[tokio::test]
    #[allow(clippy::panic, reason = "task panic is injected to prove JoinError mapping")]
    async fn lane_bounds_blocking_work_to_one_and_maps_join_errors() {
        let lane = std::sync::Arc::new(BlockingLane::new(1, 2));
        let (shutdown_tx, shutdown) = crate::daemon::shared_shutdown_channel();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let active_lane = std::sync::Arc::clone(&lane);
        let active_shutdown = shutdown.clone();
        let active = tokio::spawn(async move {
            active_lane
                .run(active_shutdown, move || {
                    started_tx.send(()).expect("active-start signal");
                    release_rx.recv().expect("release active operation");
                    Ok(())
                })
                .await
        });
        tokio::task::spawn_blocking(move || started_rx.recv().expect("active operation started"))
            .await
            .expect("start waiter");

        let queued_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let queued_lane = std::sync::Arc::clone(&lane);
        let queued_flag = std::sync::Arc::clone(&queued_called);
        let queued_shutdown = shutdown.clone();
        let queued = tokio::spawn(async move {
            queued_lane
                .run(queued_shutdown, move || {
                    queued_flag.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await
        });
        while lane.submissions.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
        assert!(matches!(
            lane.run(shutdown.clone(), || Ok(())).await,
            Err(RecordingPipelineError::QueueFull)
        ));

        shutdown_tx.send(true).expect("signal shutdown");
        assert!(matches!(
            queued.await.expect("queued lane task"),
            Err(RecordingPipelineError::Cancelled)
        ));
        assert!(!queued_called.load(Ordering::SeqCst));
        release_tx.send(()).expect("release active work");
        active.await.expect("active lane task").expect("active work completes");

        let (_lane_shutdown_tx, lane_shutdown) = crate::daemon::shared_shutdown_channel();

        let permit = std::sync::Arc::new(Semaphore::new(1)).acquire_owned().await.expect("permit");
        let submission =
            std::sync::Arc::new(Semaphore::new(1)).acquire_owned().await.expect("submission slot");
        let joined = run_blocking(permit, submission, || -> Result<(), PortError> {
            std::panic::panic_any("injected blocking panic");
        })
        .await;
        assert!(matches!(joined, Err(RecordingPipelineError::Join(error)) if error.is_panic()));

        let closed = BlockingLane::new(1, 1);
        closed.permits.close();
        assert!(matches!(
            closed.run(lane_shutdown.clone(), || Ok(())).await,
            Err(RecordingPipelineError::LaneClosed)
        ));
        assert!(matches!(
            lane.run(lane_shutdown.clone(), || Err(capture_error())).await,
            Err(RecordingPipelineError::Port(_))
        ));
        let capture = std::sync::Arc::new(FakeCapture::default());
        capture.fail_events.store(true, Ordering::SeqCst);
        let pipeline = RecordingPipeline::new(capture, EndpointObservationInput::default());
        let failure = pipeline
            .process(
                IncomingEnvelope::EventBatch(EventBatch {
                    recording_id: recording_id_bytes(),
                    events: vec![RecordingEvent { recording_seq: 1, ..RecordingEvent::default() }],
                }),
                ProjectId::new(),
                RuntimeSessionId::new(),
                lane_shutdown,
            )
            .await;
        assert!(
            matches!(failure, Err(RecordingPipelineError::Port(error)) if error.kind() == PortErrorKind::Internal)
        );
    }

    #[test]
    fn effective_mode_is_the_lower_of_armed_and_claimed() {
        use xtrace_domain::CaptureMode::{Focused, Standard};
        let focused = xtrace_domain::CAPTURE_POLICY_FOCUSED_ID;
        let standard = xtrace_domain::CAPTURE_POLICY_STANDARD_ID;
        // an unarmed session never records under the focused cap, however it is claimed
        assert_eq!(super::effective_capture_mode(Standard, focused), Standard);
        assert_eq!(super::effective_capture_mode(Standard, standard), Standard);
        assert_eq!(super::effective_capture_mode(Focused, focused), Focused);
        assert_eq!(super::effective_capture_mode(Focused, standard), Standard);
        // unknown and empty policy ids mean standard
        assert_eq!(super::effective_capture_mode(Focused, ""), Standard);
        assert_eq!(super::effective_capture_mode(Focused, "xtrace.focused.v2"), Standard);
    }

    #[test]
    fn ingest_and_application_caps_agree() {
        use xtrace_domain::CaptureMode::{Focused, Standard};
        let ingest = xtrace_ingest::IngestConfig::mode_derived(std::num::NonZeroUsize::MIN);
        for mode in [Standard, Focused] {
            assert_eq!(ingest.event_cap(mode), mode.event_cap(), "{mode:?}");
        }
        assert_eq!(Standard.event_cap(), 16_384);
        assert_eq!(Focused.event_cap(), 131_072);
    }
}
