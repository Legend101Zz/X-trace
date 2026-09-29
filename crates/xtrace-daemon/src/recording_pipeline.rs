//! Daemon-owned translation and blocking execution for recording capture.

use std::sync::Arc;

use prost::Message as _;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinError;
use uuid::Uuid;
use xtrace_application::PortError;
use xtrace_application::recording::{
    AcceptedRecordingEvent, BeginRecording, FinishRecording, RecordEvents, RecordingCapture,
};
use xtrace_domain::{ProjectId, RecordingId, RuntimeSessionId, WallTime};
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
    lane: Arc<BlockingLane>,
}

impl RecordingPipeline {
    pub(crate) fn new(capture: Arc<dyn RecordingCapture<Event = XtfEventEnvelope>>) -> Self {
        Self {
            capture,
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
                let request = translate_started(&started, project_id, runtime_session_id)?;
                let capture = Arc::clone(&self.capture);
                self.lane.run(shutdown, move || capture.begin_recording(request).map(|_| ())).await
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

fn translate_started(
    started: &RecordingStarted,
    project_id: ProjectId,
    runtime_session_id: RuntimeSessionId,
) -> Result<BeginRecording, RecordingPipelineError> {
    Ok(BeginRecording {
        project_id,
        recording_id: recording_id(&started.recording_id)?,
        runtime_session_id,
        opened_at: WallTime::now(),
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
            let payload = XtfEventEnvelope { recording_seq, event: Some(event) };
            AcceptedRecordingEvent {
                recording_seq,
                monotonic_ns,
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
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "test fixture assertions")]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;

    use prost::Message as _;
    use tokio::sync::Semaphore;
    use xtrace_application::recording::{
        BeginRecording, BeginRecordingReceipt, FinishRecordingReceipt, RecordEvents,
        RecordEventsReceipt,
    };
    use xtrace_application::{PortError, PortErrorKind};
    use xtrace_domain::{CorrelationId, ProjectId, RecordingId, RuntimeSessionId, WallTime};
    use xtrace_protocol::generated::agent::{
        CapabilitySet, EventBatch, Health, RecordingEvent, RecordingFinished, RecordingStarted,
    };

    use super::{BlockingLane, RecordingPipeline, RecordingPipelineError, run_blocking};
    use crate::runtime::IncomingEnvelope;

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
            self.operations.lock().expect("operations").push(Operation::Started(request));
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
            self.operations.lock().expect("operations").push(Operation::Finished(request));
            Ok(FinishRecordingReceipt {
                recording_id: request.recording_id,
                persisted_segments: 0,
                exact_replay: false,
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
        let pipeline = RecordingPipeline::new(capture.clone());
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
        let Operation::Started(start) = operations[0] else {
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
        let Operation::Finished(finish) = operations[3] else {
            panic!("last operation must be finish");
        };
        assert_eq!(finish.recording_id, recording_id);
        assert_eq!(finish.final_recording_seq, 3);
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
        let pipeline = RecordingPipeline::new(capture);
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
}
