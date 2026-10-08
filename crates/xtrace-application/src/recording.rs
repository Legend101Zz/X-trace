//! Recording capture use case and persistence port.
//!
//! This module owns the protocol-independent policy between admitted recording
//! events and immutable storage segments. Wire translation stays in the daemon;
//! concrete XTF/SQLite behavior stays in `xtrace-store`.

use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard};

use xtrace_domain::{CorrelationId, ProjectId, RecordingId, RuntimeSessionId, WallTime};

use crate::{PortError, PortErrorKind};

/// Maximum number of unique event digests retained, and events persisted, for
/// one recording.
///
/// This bounds memory and terminal-verification work. Events beyond it are not
/// persisted; they are dropped, counted, and the recording degrades to
/// [`RecordingCompletion::Partial`] instead of failing the capture.
pub const MAX_RECORDED_EVENTS: usize = 2_048;
/// Maximum distinct event priorities tracked for capacity drops of one
/// recording. Keeps the drop accounting bounded (the store accepts at most 256
/// priority buckets in total, adapter-reported ones included).
pub const MAX_CAPACITY_DROP_PRIORITIES: usize = 64;
const MAX_DROP_COUNT_BUCKETS: usize = 256;
/// Default maximum number of events in one immutable segment.
pub const DEFAULT_SEGMENT_EVENTS: usize = 2_000;
/// Default maximum number of recording IDs retained by one capture service.
pub const DEFAULT_MAX_RETAINED_RECORDINGS: usize = 1_024;
/// Maximum length-prefixed encoded XTF event envelope accepted by the codec.
pub const MAX_XTF_EVENT_ENVELOPE_BYTES: usize = 1024 * 1024 + 4;
/// Event-byte budget after reserving the XTF prefix, maximum header, and footer.
///
/// The event total includes four-byte length prefixes. XTF's fixed prefix is
/// twelve bytes, its header is capped at 64 KiB, and its footer is 60 bytes.
pub const DEFAULT_SEGMENT_EVENT_BYTES: usize = (4 * 1024 * 1024) - 12 - (64 * 1024) - 60;
/// Default maximum adapter-monotonic span represented by one segment.
pub const DEFAULT_SEGMENT_SPAN_NS: u64 = 2_000_000_000;

const EVENT_DIGEST_DOMAIN: &[u8] = b"xtrace.application.recording-event.v1";

/// Segment-sealing limits owned by the recording use case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentPolicy {
    max_events: usize,
    max_event_bytes: usize,
    max_span_ns: u64,
}

impl SegmentPolicy {
    /// Creates a non-zero, bounded segment policy.
    ///
    /// # Errors
    ///
    /// Returns a validation error when any limit is zero, the event limit is
    /// greater than [`DEFAULT_SEGMENT_EVENTS`], or the byte budget is greater
    /// than the XTF-safe event-byte budget.
    pub fn new(
        max_events: usize,
        max_event_bytes: usize,
        max_span_ns: u64,
    ) -> Result<Self, PortError> {
        if max_events == 0
            || max_events > DEFAULT_SEGMENT_EVENTS
            || max_event_bytes == 0
            || max_event_bytes > DEFAULT_SEGMENT_EVENT_BYTES
            || max_span_ns == 0
        {
            return Err(capture_error(
                PortErrorKind::Validation,
                "recording segment policy is outside supported bounds",
            ));
        }
        Ok(Self { max_events, max_event_bytes, max_span_ns })
    }

    /// Returns the maximum event count in one segment.
    #[must_use]
    pub const fn max_events(self) -> usize {
        self.max_events
    }

    /// Returns the maximum encoded-event byte budget in one segment.
    #[must_use]
    pub const fn max_event_bytes(self) -> usize {
        self.max_event_bytes
    }

    /// Returns the maximum adapter-monotonic span in one segment.
    #[must_use]
    pub const fn max_span_ns(self) -> u64 {
        self.max_span_ns
    }
}

impl Default for SegmentPolicy {
    fn default() -> Self {
        Self {
            max_events: DEFAULT_SEGMENT_EVENTS,
            max_event_bytes: DEFAULT_SEGMENT_EVENT_BYTES,
            max_span_ns: DEFAULT_SEGMENT_SPAN_NS,
        }
    }
}

/// Immutable identity used to open a durable recording anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeginRecording {
    /// Project that owns the recording.
    pub project_id: ProjectId,
    /// Recording identity assigned by the authenticated adapter.
    pub recording_id: RecordingId,
    /// Runtime session that admitted the recording.
    pub runtime_session_id: RuntimeSessionId,
    /// Daemon wall time chosen for the first accepted start marker.
    pub opened_at: WallTime,
    /// CLI-selected run context and untrusted adapter endpoint fields.
    pub endpoint_observation: EndpointObservationInput,
}

/// Raw start fields plus invocation-scoped operator opt-in. Rejected strings
/// are used only for in-transaction classification and are never persisted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EndpointObservationInput {
    /// Optional operator-selected policy identifier.
    pub policy_id: Option<String>,
    /// Optional paired run-scoped application component.
    pub application_component: Option<String>,
    /// Optional paired run-scoped binding key.
    pub binding_key: Option<String>,
    /// Adapter supplied method, not trusted until classified.
    pub method: String,
    /// Adapter supplied matched route template, not trusted until classified.
    pub route_template: String,
}

/// Idempotency disposition returned by a recording-anchor port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeginRecordingDisposition {
    /// A new anchor was inserted.
    Inserted,
    /// The same immutable anchor already existed.
    ExactReplay,
    /// Existing recording has no sidecar evidence; retry did not infer or add one.
    LegacyObservationAbsent,
}

/// Receipt returned by [`RecordingPersistencePort::begin_recording`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeginRecordingReceipt {
    /// Recording whose anchor was proven durable.
    pub recording_id: RecordingId,
    /// Whether the port inserted or replayed the anchor.
    pub disposition: BeginRecordingDisposition,
}

/// Immutable segment request passed to the persistence port.
#[derive(Clone, Debug)]
pub struct PersistRecordingSegment<E> {
    /// Project that owns the segment.
    pub project_id: ProjectId,
    /// Recording that owns the segment.
    pub recording_id: RecordingId,
    /// Zero-based segment ordinal.
    pub segment_ordinal: u32,
    /// Ordered event payloads with the sequence and bytes used to verify
    /// replay identity and the XTF segment size bound.
    pub events: Vec<AcceptedRecordingEvent<E>>,
}

/// Idempotency disposition returned by a segment port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistSegmentDisposition {
    /// A new immutable segment was committed.
    Inserted,
    /// The same immutable request was already committed.
    ExactReplay,
}

/// Receipt returned by [`RecordingPersistencePort::persist_segment`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistSegmentReceipt {
    /// Recording that owns the committed segment.
    pub recording_id: RecordingId,
    /// Zero-based segment ordinal that was committed.
    pub segment_ordinal: u32,
    /// Whether the port inserted or replayed the segment.
    pub disposition: PersistSegmentDisposition,
}

/// Outbound persistence contract used by recording capture.
///
/// The associated event keeps this trait object-safe without making the
/// application crate depend on generated protocol or storage types.
pub trait RecordingPersistencePort: Send + Sync {
    /// Typed event representation understood by the infrastructure adapter.
    type Event: Clone + Send + Sync + 'static;

    /// Inserts or exactly replays one immutable recording anchor.
    ///
    /// # Errors
    ///
    /// Returns a typed port failure without changing application state.
    fn begin_recording(&self, request: &BeginRecording)
    -> Result<BeginRecordingReceipt, PortError>;

    /// Validates one event's typed payload against its supplied canonical bytes.
    ///
    /// This method must be side-effect-free and must not perform persistence
    /// I/O. Capture calls it for every new event during complete batch
    /// preflight, before committing pending data or changing in-memory state.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error when the payload and its metadata or
    /// canonical bytes disagree.
    fn validate_event(&self, event: &AcceptedRecordingEvent<Self::Event>) -> Result<(), PortError>;

    /// Commits or exactly replays one immutable segment.
    ///
    /// # Errors
    ///
    /// Returns a typed port failure. Implementations must make an ambiguous
    /// retry safe by treating the complete request as idempotent.
    fn persist_segment(
        &self,
        request: &PersistRecordingSegment<Self::Event>,
    ) -> Result<PersistSegmentReceipt, PortError>;

    /// Persists and verifies terminal evidence after all segment bytes are durable.
    fn finish_recording(
        &self,
        _request: &FinishRecording,
    ) -> Result<RecordingCompletion, PortError> {
        // Ports that have not implemented durable terminal evidence cannot
        // establish completion. Keep the fallback honest for test and adapter
        // compositions while the SQLite port supplies the proof.
        Ok(RecordingCompletion::Partial)
    }
}

/// One admitted event plus the canonical bytes used for replay identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedRecordingEvent<E> {
    /// Strictly increasing recording sequence.
    pub recording_seq: u64,
    /// Adapter-monotonic timestamp used only for deterministic segmentation.
    pub monotonic_ns: u64,
    /// Adapter event priority; events dropped at capacity are counted under it.
    pub priority: u32,
    /// Canonical encoded event-envelope bytes used for digest and size checks.
    pub canonical_bytes: Vec<u8>,
    /// Typed payload passed unchanged to the persistence port.
    pub payload: E,
}

/// Batch of admitted events for one recording.
#[derive(Clone, Debug)]
pub struct RecordEvents<E> {
    /// Recording that owns every event in the batch.
    pub recording_id: RecordingId,
    /// Strictly ascending events, including exact retransmissions when present.
    pub events: Vec<AcceptedRecordingEvent<E>>,
}

/// Structural finish marker accepted by the ingest validator.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FinishRecording {
    /// Recording being sealed.
    pub recording_id: RecordingId,
    /// Highest contiguous sequence declared by the adapter.
    pub final_recording_seq: u64,
    /// Adapter-observed duration in monotonic nanoseconds.
    pub duration_ns: Option<u64>,
    /// Adapter's V1 digest over emitted event IDs in order, without separators.
    pub event_digest: Vec<u8>,
    /// Counts reported by the adapter for events dropped before emission.
    pub drop_counts_by_priority: BTreeMap<u32, u64>,
    /// Stable capability codes that were advertised but not exercised.
    pub unsupported_capability_codes: Vec<String>,
    /// Events the capture service dropped at the per-recording event capacity.
    ///
    /// Set only by the capture service, never by adapters. They are also
    /// counted in `drop_counts_by_priority` under their own priorities; this
    /// field records that those drops came from capacity, not from the adapter.
    #[serde(default)]
    pub capacity_dropped_events: u64,
    /// Producer-declared response summary; only non-preview states are accepted
    /// until a verified privacy-policy registry exists. This is not outcome proof.
    pub response_summary: Option<xtrace_domain::CapturedValue>,
}

impl FinishRecording {
    /// Constructs finish evidence for legacy callers without a digest.
    ///
    /// The absent proof is durably classified as partial by a capable port.
    #[must_use]
    pub fn without_digest(recording_id: RecordingId, final_recording_seq: u64) -> Self {
        Self {
            recording_id,
            final_recording_seq,
            duration_ns: None,
            event_digest: Vec::new(),
            drop_counts_by_priority: BTreeMap::new(),
            unsupported_capability_codes: Vec::new(),
            capacity_dropped_events: 0,
            response_summary: None,
        }
    }
}

/// Durable result of comparing a finish marker with persisted recording evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordingCompletion {
    /// Finish sequence and ID digest match, with no reported drops or gap events.
    Complete,
    /// Finish evidence is absent or capture contains a declared gap/drop.
    Partial,
    /// Finish digest or event correlation contradicts persisted events.
    Invalid,
}

/// Result of staging one event batch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordEventsReceipt {
    /// Number of newly accepted events.
    pub accepted: usize,
    /// Number of exact replay events ignored.
    pub duplicates: usize,
    /// Number of new events dropped because the per-recording event capacity
    /// ([`MAX_RECORDED_EVENTS`]) was reached. They are not persisted and are
    /// counted per event priority in the terminal evidence drop counts.
    pub dropped: usize,
    /// Number of segments made durable during the call.
    pub persisted_segments: usize,
}

/// Result of accepting a structural finish marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinishRecordingReceipt {
    /// Recording whose in-memory assembler is sealed.
    pub recording_id: RecordingId,
    /// Number of segments made durable during the call.
    pub persisted_segments: usize,
    /// True when the same finish marker was already processed.
    pub exact_replay: bool,
    /// Completion state returned by the durable persistence port.
    pub completion: RecordingCompletion,
}

/// Object-safe recording capture use case consumed by daemon composition.
pub trait RecordingCapture: Send + Sync {
    /// Typed event supplied by the daemon's protocol translator.
    type Event: Clone + Send + Sync + 'static;

    /// Opens or exactly replays one recording anchor.
    ///
    /// # Errors
    ///
    /// Returns a typed validation, conflict, resource, or persistence failure.
    fn begin_recording(&self, request: BeginRecording) -> Result<BeginRecordingReceipt, PortError>;

    /// Stages admitted events and persists every segment that reaches a seal
    /// boundary.
    ///
    /// # Errors
    ///
    /// Returns without accepting later input when an immutable pending segment
    /// cannot be retried, or when event identity/order is invalid.
    fn record_events(
        &self,
        request: RecordEvents<Self::Event>,
    ) -> Result<RecordEventsReceipt, PortError>;

    /// Flushes the remaining segment and seals the volatile assembler.
    ///
    /// This does not transition the durable recording into a terminal state.
    ///
    /// # Errors
    ///
    /// Returns a typed port failure while retaining the immutable pending
    /// segment for an exact retry.
    fn finish_recording(
        &self,
        request: FinishRecording,
    ) -> Result<FinishRecordingReceipt, PortError>;
}

/// Thread-safe recording capture service over one persistence port.
///
/// The service is intended to be daemon-scoped. Its map survives individual
/// adapter sessions, while each recording has a separate lock so unrelated
/// recordings do not serialize their in-memory assembly work. Finished
/// recordings remain retained: until cleanup or recovery is implemented, the
/// configured recording budget can be exhausted for the rest of the daemon
/// lifetime, and new recording IDs will be rejected until restart.
pub struct RecordingCaptureService<P: RecordingPersistencePort + ?Sized> {
    port: Arc<P>,
    policy: SegmentPolicy,
    max_retained_recordings: NonZeroUsize,
    recordings: Mutex<HashMap<RecordingId, SharedAssembly<P::Event>>>,
}

type SharedAssembly<E> = Arc<Mutex<RecordingAssembly<E>>>;

impl<P: RecordingPersistencePort + ?Sized> RecordingCaptureService<P> {
    /// Creates a daemon-scoped capture service with a bound on retained IDs.
    ///
    /// The bound applies across adapter sessions. Existing IDs remain
    /// retryable when the bound is full; a new ID returns a typed resource
    /// error before the persistence port is called. Finished entries are not
    /// removed, so the budget can remain exhausted until the daemon restarts.
    #[must_use]
    pub fn new(port: Arc<P>, policy: SegmentPolicy, max_retained_recordings: NonZeroUsize) -> Self {
        Self { port, policy, max_retained_recordings, recordings: Mutex::new(HashMap::new()) }
    }

    fn recording(&self, recording_id: RecordingId) -> Result<SharedAssembly<P::Event>, PortError> {
        let recordings = lock(&self.recordings)?;
        recordings.get(&recording_id).cloned().ok_or_else(|| {
            capture_error(PortErrorKind::NotFound, "recording start has not been accepted")
        })
    }

    fn release_unbegun_reservation(
        &self,
        recording_id: RecordingId,
        assembly: &SharedAssembly<P::Event>,
    ) -> Result<(), PortError> {
        let mut recordings = lock(&self.recordings)?;
        let points_to_assembly =
            recordings.get(&recording_id).is_some_and(|current| Arc::ptr_eq(current, assembly));
        if points_to_assembly && Arc::strong_count(assembly) == 2 {
            let state = lock(assembly)?;
            if !state.begun {
                recordings.remove(&recording_id);
            }
        }
        Ok(())
    }

    fn commit_pending(&self, state: &mut RecordingAssembly<P::Event>) -> Result<usize, PortError> {
        let Some(pending) = state.pending.as_ref() else {
            return Ok(0);
        };
        let request = PersistRecordingSegment {
            project_id: state.project_id,
            recording_id: state.recording_id,
            segment_ordinal: pending.segment_ordinal,
            events: pending.events.clone(),
        };
        let receipt = self.port.persist_segment(&request)?;
        if receipt.recording_id != state.recording_id
            || receipt.segment_ordinal != pending.segment_ordinal
        {
            return Err(capture_error(
                PortErrorKind::Internal,
                "recording persistence returned a mismatched segment receipt",
            ));
        }
        let committed_ordinal = pending.segment_ordinal;
        state.pending = None;
        state.next_segment_ordinal = committed_ordinal.checked_add(1);
        Ok(1)
    }

    fn seal_current(&self, state: &mut RecordingAssembly<P::Event>) -> Result<usize, PortError> {
        let mut persisted = self.commit_pending(state)?;
        if state.current_events.is_empty() {
            return Ok(persisted);
        }
        let ordinal = state.next_segment_ordinal.ok_or_else(|| {
            capture_error(PortErrorKind::Resource, "recording exhausted segment ordinals")
        })?;
        let events = std::mem::take(&mut state.current_events);
        state.current_event_bytes = 0;
        state.current_first_monotonic_ns = None;
        state.pending = Some(PendingSegment { segment_ordinal: ordinal, events });
        persisted += self.commit_pending(state)?;
        Ok(persisted)
    }

    fn stage_new_event(
        &self,
        state: &mut RecordingAssembly<P::Event>,
        event: AcceptedRecordingEvent<P::Event>,
    ) -> Result<usize, PortError> {
        let event_bytes = encoded_event_bytes(&event)?;
        if event_bytes > self.policy.max_event_bytes {
            return Err(capture_error(
                PortErrorKind::Validation,
                "recording event exceeds the segment byte budget",
            ));
        }
        if event_bytes > MAX_XTF_EVENT_ENVELOPE_BYTES {
            return Err(capture_error(
                PortErrorKind::Validation,
                "recording event exceeds the XTF envelope limit",
            ));
        }

        let span_reached = state.current_first_monotonic_ns.is_some_and(|first| {
            event.monotonic_ns.saturating_sub(first) >= self.policy.max_span_ns
        });
        let bytes_with_event =
            state.current_event_bytes.checked_add(event_bytes).ok_or_else(|| {
                capture_error(PortErrorKind::Resource, "recording segment byte count overflow")
            })?;
        let must_seal_before = !state.current_events.is_empty()
            && (state.current_events.len() >= self.policy.max_events
                || bytes_with_event > self.policy.max_event_bytes
                || span_reached);
        let mut persisted = if must_seal_before { self.seal_current(state)? } else { 0 };

        if state.current_events.is_empty() {
            state.current_first_monotonic_ns = Some(event.monotonic_ns);
        }
        state.current_event_bytes = state
            .current_event_bytes
            .checked_add(event_bytes)
            .ok_or_else(|| capture_error(PortErrorKind::Resource, "segment byte count overflow"))?;
        let sequence = event.recording_seq;
        let digest = event_digest(&event.canonical_bytes);
        state.current_events.push(event);
        state.event_digests.insert(sequence, digest);
        state.highest_contiguous = sequence;

        if state.current_events.len() == self.policy.max_events
            || state.current_event_bytes == self.policy.max_event_bytes
        {
            persisted += self.seal_current(state)?;
        }
        Ok(persisted)
    }
}

impl<P: RecordingPersistencePort + ?Sized> RecordingCapture for RecordingCaptureService<P> {
    type Event = P::Event;

    fn begin_recording(&self, request: BeginRecording) -> Result<BeginRecordingReceipt, PortError> {
        let recording = {
            let mut recordings = lock(&self.recordings)?;
            if let Some(recording) = recordings.get(&request.recording_id) {
                Arc::clone(recording)
            } else {
                if recordings.len() >= self.max_retained_recordings.get() {
                    return Err(capture_error(
                        PortErrorKind::Resource,
                        "recording capture retained-ID capacity is exhausted",
                    ));
                }
                let recording = Arc::new(Mutex::new(RecordingAssembly::new(request.clone())));
                recordings.insert(request.recording_id, Arc::clone(&recording));
                recording
            }
        };
        let mut state = lock(&recording)?;
        if state.project_id != request.project_id
            || state.runtime_session_id != request.runtime_session_id
        {
            return Err(capture_error(
                PortErrorKind::Conflict,
                "recording start conflicts with the accepted identity",
            ));
        }
        let stable = BeginRecording {
            project_id: state.project_id,
            recording_id: state.recording_id,
            runtime_session_id: state.runtime_session_id,
            opened_at: state.opened_at,
            endpoint_observation: request.endpoint_observation,
        };
        let receipt = match self.port.begin_recording(&stable) {
            Ok(receipt) => receipt,
            Err(error) => {
                let definitive = matches!(
                    error.kind(),
                    PortErrorKind::Validation
                        | PortErrorKind::AlreadyExists
                        | PortErrorKind::NotFound
                        | PortErrorKind::Conflict
                        | PortErrorKind::Compatibility
                        | PortErrorKind::Corruption
                );
                drop(state);
                if definitive {
                    self.release_unbegun_reservation(request.recording_id, &recording)?;
                }
                return Err(error);
            }
        };
        if receipt.recording_id != state.recording_id {
            return Err(capture_error(
                PortErrorKind::Internal,
                "recording persistence returned a mismatched begin receipt",
            ));
        }
        state.begun = true;
        Ok(receipt)
    }

    fn record_events(
        &self,
        request: RecordEvents<Self::Event>,
    ) -> Result<RecordEventsReceipt, PortError> {
        let recording = self.recording(request.recording_id)?;
        let mut state = lock(&recording)?;
        if !state.begun {
            return Err(capture_error(
                PortErrorKind::Conflict,
                "recording anchor has not been persisted",
            ));
        }

        let preflight = preflight_events(self.port.as_ref(), &state, &request.events, self.policy)?;
        if (state.finished || state.finish_intent.is_some())
            && (!preflight.new_events.is_empty() || preflight.dropped > 0)
        {
            return Err(capture_error(
                PortErrorKind::Conflict,
                "sealed recording cannot accept new events",
            ));
        }
        let mut receipt = RecordEventsReceipt {
            persisted_segments: self.commit_pending(&mut state)?,
            duplicates: preflight.duplicates,
            accepted: preflight.new_events.len(),
            dropped: preflight.dropped,
        };
        for event in preflight.new_events {
            receipt.persisted_segments += self.stage_new_event(&mut state, event)?;
        }
        // Counted only after staging succeeded so a retried batch recomputes
        // the same drops instead of double counting them.
        state.capacity_dropped = state.capacity_dropped.saturating_add(preflight.dropped as u64);
        state.capacity_dropped_by_priority = preflight.dropped_by_priority;
        Ok(receipt)
    }

    fn finish_recording(
        &self,
        request: FinishRecording,
    ) -> Result<FinishRecordingReceipt, PortError> {
        let recording = self.recording(request.recording_id)?;
        let mut state = lock(&recording)?;
        if !state.begun {
            return Err(capture_error(
                PortErrorKind::Conflict,
                "recording anchor has not been persisted",
            ));
        }
        if let Some(existing_request) = &state.finish_intent {
            if existing_request != &request {
                return Err(capture_error(
                    PortErrorKind::Conflict,
                    "recording finish conflicts with the accepted evidence",
                ));
            }
            if state.finished {
                let persisted_segments = self.commit_pending(&mut state)?;
                let completion =
                    self.port.finish_recording(&effective_finish(&state, &request)?)?;
                return Ok(FinishRecordingReceipt {
                    recording_id: state.recording_id,
                    persisted_segments,
                    exact_replay: true,
                    completion,
                });
            }
        }
        let mut persisted_segments = self.commit_pending(&mut state)?;
        persisted_segments += self.seal_current(&mut state)?;
        let completion = self.port.finish_recording(&effective_finish(&state, &request)?)?;
        // Only remember a finish marker once the durable port has accepted it.
        // A rejected/ambiguous attempt must leave room for an exact replay or a
        // corrected request after the caller resolves the failure.
        state.finish_intent = Some(request);
        state.finished = true;
        Ok(FinishRecordingReceipt {
            recording_id: state.recording_id,
            persisted_segments,
            exact_replay: false,
            completion,
        })
    }
}

struct RecordingAssembly<E> {
    project_id: ProjectId,
    recording_id: RecordingId,
    runtime_session_id: RuntimeSessionId,
    opened_at: WallTime,
    begun: bool,
    /// Highest sequence that was persisted or staged (not dropped).
    highest_contiguous: u64,
    /// Contiguous events after `highest_contiguous` dropped at capacity.
    capacity_dropped: u64,
    /// The same drops by their own event priority (bounded bucket count).
    capacity_dropped_by_priority: BTreeMap<u32, u64>,
    event_digests: BTreeMap<u64, [u8; 32]>,
    current_events: Vec<AcceptedRecordingEvent<E>>,
    current_event_bytes: usize,
    current_first_monotonic_ns: Option<u64>,
    next_segment_ordinal: Option<u32>,
    pending: Option<PendingSegment<E>>,
    finish_intent: Option<FinishRecording>,
    finished: bool,
}

impl<E> RecordingAssembly<E> {
    fn new(request: BeginRecording) -> Self {
        Self {
            project_id: request.project_id,
            recording_id: request.recording_id,
            runtime_session_id: request.runtime_session_id,
            opened_at: request.opened_at,
            begun: false,
            highest_contiguous: 1,
            capacity_dropped: 0,
            capacity_dropped_by_priority: BTreeMap::new(),
            event_digests: BTreeMap::new(),
            current_events: Vec::new(),
            current_event_bytes: 0,
            current_first_monotonic_ns: None,
            next_segment_ordinal: Some(0),
            pending: None,
            finish_intent: None,
            finished: false,
        }
    }
}

struct PendingSegment<E> {
    segment_ordinal: u32,
    events: Vec<AcceptedRecordingEvent<E>>,
}

struct Preflight<E> {
    duplicates: usize,
    dropped: usize,
    dropped_by_priority: BTreeMap<u32, u64>,
    new_events: Vec<AcceptedRecordingEvent<E>>,
}

fn preflight_events<P: RecordingPersistencePort + ?Sized>(
    port: &P,
    state: &RecordingAssembly<P::Event>,
    events: &[AcceptedRecordingEvent<P::Event>],
    policy: SegmentPolicy,
) -> Result<Preflight<P::Event>, PortError> {
    // Sequences after `highest_contiguous` up to `scratch_highest` were
    // observed but dropped at capacity; they carry no digest by design, so the
    // retained state stays bounded by MAX_RECORDED_EVENTS.
    let persisted_highest = state.highest_contiguous;
    let mut scratch_highest = persisted_highest.saturating_add(state.capacity_dropped);
    let mut scratch_digests = state.event_digests.clone();
    let mut previous_input = None;
    let mut duplicates = 0usize;
    let mut dropped = 0usize;
    let mut dropped_by_priority = state.capacity_dropped_by_priority.clone();
    let mut new_events = Vec::new();

    for event in events {
        if previous_input.is_some_and(|previous| event.recording_seq <= previous) {
            return Err(capture_error(
                PortErrorKind::Validation,
                "recording batch sequences must be strictly ascending",
            ));
        }
        previous_input = Some(event.recording_seq);
        port.validate_event(event)?;
        let digest = event_digest(&event.canonical_bytes);
        if let Some(existing) = scratch_digests.get(&event.recording_seq) {
            if existing != &digest {
                return Err(capture_error(
                    PortErrorKind::Conflict,
                    "recording event replay changed its canonical payload",
                ));
            }
            duplicates += 1;
            continue;
        }
        if event.recording_seq > persisted_highest && event.recording_seq <= scratch_highest {
            // Replay of an event already dropped at capacity: nothing was
            // persisted, so there is no payload to compare and no new drop.
            duplicates += 1;
            continue;
        }
        let expected = scratch_highest.checked_add(1).ok_or_else(|| {
            capture_error(PortErrorKind::Conflict, "recording sequence is exhausted")
        })?;
        if event.recording_seq != expected {
            return Err(capture_error(
                PortErrorKind::Conflict,
                "recording event sequence is not contiguous",
            ));
        }
        let event_bytes = encoded_event_bytes(event)?;
        if event_bytes > policy.max_event_bytes || event_bytes > MAX_XTF_EVENT_ENVELOPE_BYTES {
            return Err(capture_error(
                PortErrorKind::Validation,
                "recording event exceeds a segment or XTF envelope byte limit",
            ));
        }
        if scratch_digests.len() >= MAX_RECORDED_EVENTS {
            // Bounded capacity: degrade honestly instead of killing capture.
            // The event is neither persisted nor retained, only counted.
            if !dropped_by_priority.contains_key(&event.priority)
                && dropped_by_priority.len() >= MAX_CAPACITY_DROP_PRIORITIES
            {
                return Err(capture_error(
                    PortErrorKind::Resource,
                    "recording capacity-drop priority buckets are exhausted",
                ));
            }
            let bucket = dropped_by_priority.entry(event.priority).or_insert(0);
            *bucket = bucket.saturating_add(1);
            dropped += 1;
            scratch_highest = event.recording_seq;
            continue;
        }
        scratch_highest = event.recording_seq;
        scratch_digests.insert(event.recording_seq, digest);
        new_events.push(event.clone());
    }
    Ok(Preflight { duplicates, dropped, dropped_by_priority, new_events })
}

/// Returns the finish evidence handed to the persistence port.
///
/// When events were dropped at capacity the adapter's digest covers events that
/// were never persisted, so it can no longer be verified: it is withheld (the
/// store then labels the recording `Partial`, never `Complete` or a false
/// `Invalid`). Each dropped event is added to the bucket of its own priority,
/// and the total is recorded in `capacity_dropped_events` so the origin of the
/// drops stays explicit. The result is a pure function of the accepted request
/// and the frozen drop counts, so exact replays stay byte-identical.
fn effective_finish<E>(
    state: &RecordingAssembly<E>,
    request: &FinishRecording,
) -> Result<FinishRecording, PortError> {
    if state.capacity_dropped == 0 {
        return Ok(request.clone());
    }
    let mut effective = request.clone();
    effective.event_digest = Vec::new();
    effective.capacity_dropped_events =
        effective.capacity_dropped_events.saturating_add(state.capacity_dropped);
    for (priority, count) in &state.capacity_dropped_by_priority {
        let entry = effective.drop_counts_by_priority.entry(*priority).or_insert(0);
        *entry = entry.saturating_add(*count);
    }
    if effective.drop_counts_by_priority.len() > MAX_DROP_COUNT_BUCKETS {
        return Err(capture_error(
            PortErrorKind::Resource,
            "recording drop-count priority buckets are exhausted",
        ));
    }
    Ok(effective)
}

fn encoded_event_bytes<E>(event: &AcceptedRecordingEvent<E>) -> Result<usize, PortError> {
    if event.canonical_bytes.is_empty() {
        return Err(capture_error(
            PortErrorKind::Validation,
            "recording event canonical bytes must not be empty",
        ));
    }
    event.canonical_bytes.len().checked_add(4).ok_or_else(|| {
        capture_error(PortErrorKind::Resource, "recording event byte count overflow")
    })
}

fn event_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EVENT_DIGEST_DOMAIN);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, PortError> {
    mutex.lock().map_err(|_| {
        capture_error(PortErrorKind::Internal, "recording capture state lock is poisoned")
    })
}

fn capture_error(kind: PortErrorKind, message: &'static str) -> PortError {
    PortError::new(kind, message, CorrelationId::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestEvent {
        sequence: u64,
        body: u8,
    }

    #[derive(Default)]
    struct FakeState {
        begins: Vec<BeginRecording>,
        segments: Vec<PersistRecordingSegment<TestEvent>>,
    }

    #[derive(Default)]
    struct FakePort {
        state: Mutex<FakeState>,
        fail_next_segment_after_record: AtomicBool,
        finishes: Mutex<Vec<FinishRecording>>,
    }

    impl FakePort {
        fn snapshot(&self) -> FakeState {
            let state = self.state.lock().expect("fake state");
            FakeState { begins: state.begins.clone(), segments: state.segments.clone() }
        }
    }

    impl RecordingPersistencePort for FakePort {
        type Event = TestEvent;

        fn begin_recording(
            &self,
            request: &BeginRecording,
        ) -> Result<BeginRecordingReceipt, PortError> {
            let mut state = self.state.lock().expect("fake state");
            let disposition = match state
                .begins
                .iter()
                .find(|accepted| accepted.recording_id == request.recording_id)
            {
                None => BeginRecordingDisposition::Inserted,
                Some(accepted)
                    if accepted.project_id == request.project_id
                        && accepted.runtime_session_id == request.runtime_session_id
                        && accepted.opened_at == request.opened_at =>
                {
                    BeginRecordingDisposition::ExactReplay
                }
                Some(_) => {
                    return Err(capture_error(PortErrorKind::Conflict, "fake begin conflict"));
                }
            };
            state.begins.push(request.clone());
            Ok(BeginRecordingReceipt { recording_id: request.recording_id, disposition })
        }

        fn validate_event(
            &self,
            _event: &AcceptedRecordingEvent<Self::Event>,
        ) -> Result<(), PortError> {
            Ok(())
        }

        fn persist_segment(
            &self,
            request: &PersistRecordingSegment<Self::Event>,
        ) -> Result<PersistSegmentReceipt, PortError> {
            let mut state = self.state.lock().expect("fake state");
            let existing = state.segments.iter().find(|segment| {
                segment.recording_id == request.recording_id
                    && segment.segment_ordinal == request.segment_ordinal
            });
            let disposition = if let Some(existing) = existing {
                if existing.events != request.events {
                    return Err(capture_error(PortErrorKind::Conflict, "fake segment conflict"));
                }
                PersistSegmentDisposition::ExactReplay
            } else {
                PersistSegmentDisposition::Inserted
            };
            state.segments.push(request.clone());
            if self.fail_next_segment_after_record.swap(false, Ordering::SeqCst) {
                return Err(capture_error(PortErrorKind::Transport, "injected ambiguous failure"));
            }
            Ok(PersistSegmentReceipt {
                recording_id: request.recording_id,
                segment_ordinal: request.segment_ordinal,
                disposition,
            })
        }

        fn finish_recording(
            &self,
            request: &FinishRecording,
        ) -> Result<RecordingCompletion, PortError> {
            if request.unsupported_capability_codes.len() > 64
                || request.unsupported_capability_codes.iter().any(|code| {
                    let mut bytes = code.bytes();
                    !bytes.next().is_some_and(|first| first.is_ascii_lowercase())
                        || code.len() > 128
                        || !bytes.all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                        })
                })
            {
                return Err(capture_error(
                    PortErrorKind::Validation,
                    "fake finish validation failure",
                ));
            }
            self.finishes.lock().expect("finishes").push(request.clone());
            Ok(if request.event_digest.len() == 32 {
                RecordingCompletion::Complete
            } else {
                RecordingCompletion::Partial
            })
        }
    }

    #[derive(Default)]
    struct BeginFailurePort {
        attempts: Mutex<Vec<BeginRecording>>,
        next_error: Mutex<Option<PortError>>,
        fail_on_call: usize,
    }

    impl BeginFailurePort {
        fn failing_once(kind: PortErrorKind) -> Self {
            Self::failing_on_call(0, kind)
        }

        fn failing_on_call(call: usize, kind: PortErrorKind) -> Self {
            Self {
                attempts: Mutex::new(Vec::new()),
                next_error: Mutex::new(Some(capture_error(kind, "injected begin failure"))),
                fail_on_call: call,
            }
        }
    }

    impl RecordingPersistencePort for BeginFailurePort {
        type Event = TestEvent;

        fn begin_recording(
            &self,
            request: &BeginRecording,
        ) -> Result<BeginRecordingReceipt, PortError> {
            let call = {
                let mut attempts = self.attempts.lock().expect("begin attempts");
                let call = attempts.len();
                attempts.push(request.clone());
                call
            };
            if call == self.fail_on_call {
                if let Some(error) = self.next_error.lock().expect("begin error").take() {
                    return Err(error);
                }
            }
            Ok(BeginRecordingReceipt {
                recording_id: request.recording_id,
                disposition: BeginRecordingDisposition::Inserted,
            })
        }

        fn validate_event(
            &self,
            _event: &AcceptedRecordingEvent<Self::Event>,
        ) -> Result<(), PortError> {
            Ok(())
        }

        fn persist_segment(
            &self,
            request: &PersistRecordingSegment<Self::Event>,
        ) -> Result<PersistSegmentReceipt, PortError> {
            Ok(PersistSegmentReceipt {
                recording_id: request.recording_id,
                segment_ordinal: request.segment_ordinal,
                disposition: PersistSegmentDisposition::Inserted,
            })
        }
    }

    struct ConcurrentBeginFailurePort {
        calls: AtomicUsize,
        first_entered: std::sync::mpsc::Sender<()>,
        release_first: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl RecordingPersistencePort for ConcurrentBeginFailurePort {
        type Event = TestEvent;

        fn begin_recording(
            &self,
            request: &BeginRecording,
        ) -> Result<BeginRecordingReceipt, PortError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                self.first_entered
                    .send(())
                    .map_err(|_| capture_error(PortErrorKind::Internal, "test signal closed"))?;
                self.release_first
                    .lock()
                    .map_err(|_| capture_error(PortErrorKind::Internal, "test gate poisoned"))?
                    .recv()
                    .map_err(|_| capture_error(PortErrorKind::Internal, "test gate closed"))?;
            }
            if call < 2 {
                return Err(capture_error(PortErrorKind::Conflict, "injected definitive failure"));
            }
            Ok(BeginRecordingReceipt {
                recording_id: request.recording_id,
                disposition: BeginRecordingDisposition::Inserted,
            })
        }

        fn validate_event(
            &self,
            _event: &AcceptedRecordingEvent<Self::Event>,
        ) -> Result<(), PortError> {
            Ok(())
        }

        fn persist_segment(
            &self,
            request: &PersistRecordingSegment<Self::Event>,
        ) -> Result<PersistSegmentReceipt, PortError> {
            Ok(PersistSegmentReceipt {
                recording_id: request.recording_id,
                segment_ordinal: request.segment_ordinal,
                disposition: PersistSegmentDisposition::Inserted,
            })
        }
    }

    fn id<T: From<Uuid>>(seed: u8) -> T {
        T::from(Uuid::from_bytes([seed; 16]))
    }

    fn wall(second: u8) -> WallTime {
        WallTime::from_parts(2026, 9, 29, 1, 2, second, 0).expect("fixed wall time")
    }

    fn begin(opened_at: WallTime) -> BeginRecording {
        BeginRecording {
            project_id: id(0x11),
            recording_id: id(0x22),
            runtime_session_id: id(0x33),
            opened_at,
            endpoint_observation: EndpointObservationInput::default(),
        }
    }

    fn event(sequence: u64, monotonic_ns: u64, body: u8) -> AcceptedRecordingEvent<TestEvent> {
        AcceptedRecordingEvent {
            recording_seq: sequence,
            monotonic_ns,
            priority: 0,
            canonical_bytes: vec![body, u8::try_from(sequence & 0xff).expect("masked sequence")],
            payload: TestEvent { sequence, body },
        }
    }

    fn service(port: Arc<FakePort>, policy: SegmentPolicy) -> RecordingCaptureService<FakePort> {
        RecordingCaptureService::new(
            port,
            policy,
            NonZeroUsize::new(DEFAULT_MAX_RETAINED_RECORDINGS).expect("non-zero recording limit"),
        )
    }

    #[test]
    fn recording_capacity_keeps_existing_ids_retryable_and_rejects_new_ids_without_io() {
        let port = Arc::new(FakePort::default());
        let service = RecordingCaptureService::new(
            Arc::clone(&port),
            SegmentPolicy::default(),
            NonZeroUsize::new(2).expect("non-zero recording limit"),
        );
        let first = begin(wall(1));
        let second = BeginRecording { recording_id: id(0x44), ..first.clone() };
        service.begin_recording(first.clone()).expect("first recording");
        service.begin_recording(second.clone()).expect("second recording fills limit");
        let at_capacity = port.snapshot();
        assert_eq!(at_capacity.begins.len(), 2);

        let replay = service
            .begin_recording(BeginRecording { opened_at: wall(2), ..first.clone() })
            .expect("existing ID remains retryable at capacity");
        assert_eq!(replay.disposition, BeginRecordingDisposition::ExactReplay);
        let before_new_id = port.snapshot();
        assert_eq!(before_new_id.begins.len(), 3);
        assert_eq!(before_new_id.begins.last().expect("replay call").opened_at, wall(1));

        let third = BeginRecording { recording_id: id(0x55), ..first.clone() };
        let error = service.begin_recording(third.clone()).expect_err("new ID at capacity");
        assert_eq!(error.kind(), PortErrorKind::Resource);
        assert_eq!(port.snapshot().begins, before_new_id.begins);

        service
            .begin_recording(BeginRecording { opened_at: wall(2), ..second.clone() })
            .expect("second existing ID remains present");
        assert_eq!(port.snapshot().begins.len(), 4);
        assert_eq!(
            service.recording(third.recording_id).err().map(|error| error.kind()),
            Some(PortErrorKind::NotFound),
        );
    }

    #[test]
    fn definitive_begin_errors_release_new_reservations_for_all_definitive_kinds() {
        for kind in [
            PortErrorKind::Validation,
            PortErrorKind::AlreadyExists,
            PortErrorKind::NotFound,
            PortErrorKind::Conflict,
            PortErrorKind::Compatibility,
            PortErrorKind::Corruption,
        ] {
            let port = Arc::new(BeginFailurePort::failing_once(kind));
            let service = RecordingCaptureService::new(
                Arc::clone(&port),
                SegmentPolicy::default(),
                NonZeroUsize::new(1).expect("non-zero recording limit"),
            );
            let rejected = begin(wall(1));
            let error = service.begin_recording(rejected.clone()).expect_err("injected failure");
            assert_eq!(error.kind(), kind);

            let distinct = BeginRecording { recording_id: id(0x77), ..rejected.clone() };
            service.begin_recording(distinct).expect("definitive failure released capacity");
            assert_eq!(port.attempts.lock().expect("attempts").len(), 2);
        }
    }

    #[test]
    fn serialized_definitive_failures_release_after_the_last_caller() {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let port = Arc::new(ConcurrentBeginFailurePort {
            calls: AtomicUsize::new(0),
            first_entered: entered_tx,
            release_first: Mutex::new(release_rx),
        });
        let service = Arc::new(RecordingCaptureService::new(
            Arc::clone(&port),
            SegmentPolicy::default(),
            NonZeroUsize::new(1).expect("non-zero recording limit"),
        ));
        let request = begin(wall(1));
        let first_service = Arc::clone(&service);
        let first_request = request.clone();
        let first = std::thread::spawn(move || first_service.begin_recording(first_request));
        entered_rx.recv_timeout(Duration::from_secs(5)).expect("first port call entered");

        let second_service = Arc::clone(&service);
        let second_request = request.clone();
        let second = std::thread::spawn(move || second_service.begin_recording(second_request));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let owners = service
                .recordings
                .lock()
                .expect("recordings")
                .get(&request.recording_id)
                .map(Arc::strong_count)
                .unwrap_or_default();
            if owners >= 3 {
                break;
            }
            assert!(Instant::now() < deadline, "second begin did not retain the assembly");
            std::thread::yield_now();
        }

        release_tx.send(()).expect("release first port call");
        assert_eq!(
            first.join().expect("first begin thread").expect_err("first failure").kind(),
            PortErrorKind::Conflict
        );
        assert_eq!(
            second.join().expect("second begin thread").expect_err("second failure").kind(),
            PortErrorKind::Conflict
        );

        let distinct = BeginRecording { recording_id: id(0x77), ..request.clone() };
        service.begin_recording(distinct).expect("last definitive failure released capacity");
        assert_eq!(port.calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn later_definitive_begin_error_does_not_remove_a_begun_recording() {
        let port = Arc::new(BeginFailurePort::failing_on_call(1, PortErrorKind::Conflict));
        let service = RecordingCaptureService::new(
            Arc::clone(&port),
            SegmentPolicy::default(),
            NonZeroUsize::new(1).expect("non-zero recording limit"),
        );
        let begun = begin(wall(1));
        service.begin_recording(begun.clone()).expect("first begin succeeds");
        let error = service
            .begin_recording(BeginRecording { opened_at: wall(2), ..begun.clone() })
            .expect_err("later retry fails definitively");
        assert_eq!(error.kind(), PortErrorKind::Conflict);

        let distinct = BeginRecording { recording_id: id(0x77), ..begun.clone() };
        let capacity_error =
            service.begin_recording(distinct).expect_err("begun reservation remains retained");
        assert_eq!(capacity_error.kind(), PortErrorKind::Resource);
        assert_eq!(port.attempts.lock().expect("attempts").len(), 2);
    }

    #[test]
    fn begin_reservation_cleanup_retains_an_assembly_with_another_live_owner() {
        let port = Arc::new(FakePort::default());
        let service = RecordingCaptureService::new(
            port,
            SegmentPolicy::default(),
            NonZeroUsize::new(1).expect("non-zero recording limit"),
        );
        let request = begin(wall(1));
        let assembly = Arc::new(Mutex::new(RecordingAssembly::new(request.clone())));
        service
            .recordings
            .lock()
            .expect("recordings")
            .insert(request.recording_id, Arc::clone(&assembly));
        let concurrent_owner = Arc::clone(&assembly);

        service
            .release_unbegun_reservation(request.recording_id, &assembly)
            .expect("conservative cleanup");
        assert!(service.recordings.lock().expect("recordings").contains_key(&request.recording_id));

        drop(concurrent_owner);
        service
            .release_unbegun_reservation(request.recording_id, &assembly)
            .expect("unreferenced cleanup");
        assert!(
            !service.recordings.lock().expect("recordings").contains_key(&request.recording_id)
        );
    }

    #[test]
    fn ambiguous_begin_errors_retain_identity_and_capacity_for_retry() {
        for kind in [PortErrorKind::Resource, PortErrorKind::Transport, PortErrorKind::Internal] {
            let port = Arc::new(BeginFailurePort::failing_once(kind));
            let service = RecordingCaptureService::new(
                Arc::clone(&port),
                SegmentPolicy::default(),
                NonZeroUsize::new(1).expect("non-zero recording limit"),
            );
            let first = begin(wall(1));
            let error = service.begin_recording(first.clone()).expect_err("injected failure");
            assert_eq!(error.kind(), kind);

            let distinct = BeginRecording { recording_id: id(0x77), ..first.clone() };
            let capacity_error =
                service.begin_recording(distinct).expect_err("ambiguous reservation is retained");
            assert_eq!(capacity_error.kind(), PortErrorKind::Resource);
            assert_eq!(port.attempts.lock().expect("attempts").len(), 1);

            service
                .begin_recording(BeginRecording { opened_at: wall(2), ..first.clone() })
                .expect("same ID can retry");
            let attempts = port.attempts.lock().expect("attempts");
            assert_eq!(attempts.len(), 2);
            assert_eq!(attempts[0].opened_at, wall(1));
            assert_eq!(attempts[1].opened_at, wall(1));
        }
    }

    #[test]
    fn begin_retry_reuses_the_first_opened_at_through_the_port() {
        let port = Arc::new(FakePort::default());
        let service = service(Arc::clone(&port), SegmentPolicy::default());

        let inserted = service.begin_recording(begin(wall(1))).expect("first begin");
        assert_eq!(inserted.disposition, BeginRecordingDisposition::Inserted);
        let replay = service.begin_recording(begin(wall(2))).expect("retry begin");
        assert_eq!(replay.disposition, BeginRecordingDisposition::ExactReplay);

        let snapshot = port.snapshot();
        assert_eq!(snapshot.begins.len(), 2);
        assert_eq!(snapshot.begins[0].opened_at, wall(1));
        assert_eq!(snapshot.begins[1].opened_at, wall(1));
    }

    #[test]
    fn exact_duplicate_replays_and_changed_payload_does_not_poison_original() {
        let port = Arc::new(FakePort::default());
        let service = service(Arc::clone(&port), SegmentPolicy::default());
        service.begin_recording(begin(wall(1))).expect("begin");
        let original = event(2, 10, 0xaa);

        let first = service
            .record_events(RecordEvents {
                recording_id: begin(wall(1)).recording_id,
                events: vec![original.clone()],
            })
            .expect("accept original");
        assert_eq!(first.accepted, 1);

        let duplicate = service
            .record_events(RecordEvents {
                recording_id: begin(wall(1)).recording_id,
                events: vec![original.clone()],
            })
            .expect("accept exact duplicate");
        assert_eq!(duplicate.duplicates, 1);

        let changed = service.record_events(RecordEvents {
            recording_id: begin(wall(1)).recording_id,
            events: vec![event(2, 10, 0xbb)],
        });
        assert_eq!(changed.expect_err("changed replay rejected").kind(), PortErrorKind::Conflict);

        let retry = service
            .record_events(RecordEvents {
                recording_id: begin(wall(1)).recording_id,
                events: vec![original],
            })
            .expect("original remains replayable");
        assert_eq!(retry.duplicates, 1);
        assert!(port.snapshot().segments.is_empty());
    }

    #[test]
    fn gap_and_max_monotonic_values_are_checked_without_mutation_or_overflow() {
        let port = Arc::new(FakePort::default());
        let policy = SegmentPolicy::new(2_000, DEFAULT_SEGMENT_EVENT_BYTES, 4).expect("policy");
        let service = service(Arc::clone(&port), policy);
        service.begin_recording(begin(wall(1))).expect("begin");
        let recording_id = begin(wall(1)).recording_id;
        service
            .record_events(RecordEvents {
                recording_id,
                events: vec![event(2, u64::MAX - 3, 0xa2)],
            })
            .expect("first event");

        let gap = service
            .record_events(RecordEvents { recording_id, events: vec![event(4, u64::MAX, 0xa4)] });
        assert_eq!(gap.expect_err("gap rejected").kind(), PortErrorKind::Conflict);
        assert!(port.snapshot().segments.is_empty(), "gap must not seal or mutate");

        let accepted = service
            .record_events(RecordEvents { recording_id, events: vec![event(3, u64::MAX, 0xa3)] })
            .expect("contiguous event at max clock");
        assert_eq!(accepted.accepted, 1);
        assert_eq!(accepted.persisted_segments, 0);
        service.finish_recording(FinishRecording::without_digest(recording_id, 3)).expect("finish");
        let segments = port.snapshot().segments;
        assert_eq!(segments.len(), 1);
        assert_eq!(
            segments[0].events.iter().map(|event| event.payload.sequence).collect::<Vec<_>>(),
            [2, 3]
        );
    }

    #[test]
    fn count_span_and_byte_boundaries_produce_deterministic_segments() {
        let count_port = Arc::new(FakePort::default());
        let count_policy = SegmentPolicy::new(2, DEFAULT_SEGMENT_EVENT_BYTES, 10).expect("policy");
        let count_service = service(Arc::clone(&count_port), count_policy);
        count_service.begin_recording(begin(wall(1))).expect("begin");
        let recording_id = begin(wall(1)).recording_id;
        count_service
            .record_events(RecordEvents {
                recording_id,
                events: vec![event(2, 0, 2), event(3, 1, 3), event(4, 2, 4), event(5, 12, 5)],
            })
            .expect("stage count and span boundaries");
        count_service
            .finish_recording(FinishRecording::without_digest(recording_id, 5))
            .expect("finish");
        let segments = count_port.snapshot().segments;
        let sequences: Vec<Vec<u64>> = segments
            .iter()
            .map(|segment| segment.events.iter().map(|event| event.payload.sequence).collect())
            .collect();
        assert_eq!(sequences, [vec![2, 3], vec![4], vec![5]]);

        let byte_port = Arc::new(FakePort::default());
        let byte_policy = SegmentPolicy::new(10, 6, DEFAULT_SEGMENT_SPAN_NS).expect("policy");
        let byte_service = service(Arc::clone(&byte_port), byte_policy);
        byte_service.begin_recording(begin(wall(1))).expect("begin");
        byte_service
            .record_events(RecordEvents {
                recording_id,
                events: vec![event(2, 0, 2), event(3, 1, 3)],
            })
            .expect("byte boundary");
        byte_service
            .finish_recording(FinishRecording::without_digest(recording_id, 3))
            .expect("finish");
        let byte_sequences: Vec<Vec<u64>> = byte_port
            .snapshot()
            .segments
            .iter()
            .map(|segment| segment.events.iter().map(|event| event.payload.sequence).collect())
            .collect();
        assert_eq!(byte_sequences, [vec![2], vec![3]]);
    }

    #[test]
    fn default_policy_seals_at_two_thousand_events_and_two_seconds() {
        let count_port = Arc::new(FakePort::default());
        let count_service = service(Arc::clone(&count_port), SegmentPolicy::default());
        count_service.begin_recording(begin(wall(1))).expect("begin");
        let recording_id = begin(wall(1)).recording_id;
        let events = (2..=2_002)
            .map(|sequence| event(sequence, sequence, u8::try_from(sequence % 251).expect("byte")))
            .collect();
        count_service.record_events(RecordEvents { recording_id, events }).expect("events");
        let count_segments = count_port.snapshot().segments;
        assert_eq!(count_segments.len(), 1);
        assert_eq!(count_segments[0].events.len(), DEFAULT_SEGMENT_EVENTS);

        count_service
            .finish_recording(FinishRecording::without_digest(recording_id, 2_002))
            .expect("finish");
        let count_segments = count_port.snapshot().segments;
        assert_eq!(count_segments.len(), 2);
        assert_eq!(count_segments[1].events.len(), 1);

        let span_port = Arc::new(FakePort::default());
        let span_service = service(Arc::clone(&span_port), SegmentPolicy::default());
        span_service.begin_recording(begin(wall(1))).expect("begin");
        span_service
            .record_events(RecordEvents {
                recording_id,
                events: vec![event(2, 0, 2), event(3, DEFAULT_SEGMENT_SPAN_NS, 3)],
            })
            .expect("span boundary");
        let span_segments = span_port.snapshot().segments;
        assert_eq!(span_segments.len(), 1);
        assert_eq!(span_segments[0].events[0].recording_seq, 2);
        span_service
            .finish_recording(FinishRecording::without_digest(recording_id, 3))
            .expect("finish");
        let span_segments = span_port.snapshot().segments;
        assert_eq!(span_segments.len(), 2);
        assert_eq!(span_segments[1].events[0].recording_seq, 3);
    }

    #[test]
    fn invalid_batch_preflight_does_not_retry_or_apply_pending_events() {
        let port = Arc::new(FakePort::default());
        port.fail_next_segment_after_record.store(true, Ordering::SeqCst);
        let policy = SegmentPolicy::new(1, DEFAULT_SEGMENT_EVENT_BYTES, DEFAULT_SEGMENT_SPAN_NS)
            .expect("policy");
        let service = service(Arc::clone(&port), policy);
        service.begin_recording(begin(wall(1))).expect("begin");
        let recording_id = begin(wall(1)).recording_id;
        let failed =
            service.record_events(RecordEvents { recording_id, events: vec![event(2, 0, 2)] });
        assert_eq!(failed.expect_err("ambiguous write").kind(), PortErrorKind::Transport);

        let invalid = service.record_events(RecordEvents {
            recording_id,
            events: vec![event(3, 1, 3), event(5, 2, 5)],
        });
        assert_eq!(invalid.expect_err("gap rejected").kind(), PortErrorKind::Conflict);
        assert_eq!(port.snapshot().segments.len(), 1, "invalid input must not retry pending IO");

        let replay = service
            .record_events(RecordEvents { recording_id, events: vec![event(2, 0, 2)] })
            .expect("pending retry");
        assert_eq!(replay.persisted_segments, 1);
        assert_eq!(replay.duplicates, 1);
    }

    #[test]
    fn oversized_late_batch_event_does_not_apply_earlier_events() {
        let port = Arc::new(FakePort::default());
        let service = service(Arc::clone(&port), SegmentPolicy::default());
        service.begin_recording(begin(wall(1))).expect("begin");
        let recording_id = begin(wall(1)).recording_id;
        let mut oversized = event(3, 1, 3);
        oversized.canonical_bytes.resize(MAX_XTF_EVENT_ENVELOPE_BYTES, 0);
        let invalid = service
            .record_events(RecordEvents { recording_id, events: vec![event(2, 0, 2), oversized] });
        assert_eq!(
            invalid.expect_err("oversized event rejected").kind(),
            PortErrorKind::Validation
        );
        assert!(port.snapshot().segments.is_empty());

        let accepted = service
            .record_events(RecordEvents { recording_id, events: vec![event(2, 0, 2)] })
            .expect("first event remains unconsumed");
        assert_eq!(accepted.accepted, 1);
    }

    #[test]
    fn sequence_at_u64_max_is_accepted_and_cannot_wrap() {
        let port = Arc::new(FakePort::default());
        let service = service(Arc::clone(&port), SegmentPolicy::default());
        service.begin_recording(begin(wall(1))).expect("begin");
        let recording_id = begin(wall(1)).recording_id;
        let recording = service.recording(recording_id).expect("recording");
        let mut state = recording.lock().expect("assembly lock");
        state.highest_contiguous = u64::MAX - 1;
        drop(state);

        let last = event(u64::MAX, 1, 0xff);
        let accepted = service
            .record_events(RecordEvents { recording_id, events: vec![last.clone()] })
            .expect("max sequence");
        assert_eq!(accepted.accepted, 1);
        let duplicate = service
            .record_events(RecordEvents { recording_id, events: vec![last] })
            .expect("max sequence replay");
        assert_eq!(duplicate.duplicates, 1);
        let impossible_successor = service.record_events(RecordEvents {
            recording_id,
            events: vec![event(u64::MAX - 1, 2, 0xfe)],
        });
        assert_eq!(
            impossible_successor.expect_err("sequence cannot wrap").kind(),
            PortErrorKind::Conflict
        );
        assert_eq!(
            service
                .recording(recording_id)
                .expect("recording")
                .lock()
                .expect("lock")
                .highest_contiguous,
            u64::MAX
        );
    }

    fn capacity_events(first: u64, last: u64) -> Vec<AcceptedRecordingEvent<TestEvent>> {
        (first..=last)
            .map(|sequence| AcceptedRecordingEvent {
                priority: capacity_priority(sequence),
                ..event(sequence, sequence, (sequence % 251) as u8)
            })
            .collect()
    }

    /// Cycles 0, 10, 20 so priority 0 (a legitimate adapter bucket) is exercised.
    fn capacity_priority(sequence: u64) -> u32 {
        u32::try_from(sequence % 3).expect("small") * 10
    }

    fn persisted_sequences(port: &FakePort) -> Vec<u64> {
        port.snapshot()
            .segments
            .iter()
            .flat_map(|segment| segment.events.iter().map(|event| event.recording_seq))
            .collect()
    }

    #[test]
    fn events_beyond_capacity_are_dropped_counted_and_finish_partial() {
        // Intended contract change (owner-ordered F5): reaching the event
        // capacity used to fail capture with a Resource error. It now drops and
        // counts the excess and the recording ends Partial.
        let port = Arc::new(FakePort::default());
        let service = service(Arc::clone(&port), SegmentPolicy::default());
        service.begin_recording(begin(wall(1))).expect("begin");
        let recording_id = begin(wall(1)).recording_id;
        let last_kept = 1 + MAX_RECORDED_EVENTS as u64;

        let mut accepted = 0;
        for chunk_start in (2..=last_kept).step_by(500) {
            let chunk_end = (chunk_start + 499).min(last_kept);
            let receipt = service
                .record_events(RecordEvents {
                    recording_id,
                    events: capacity_events(chunk_start, chunk_end),
                })
                .expect("events within capacity");
            assert_eq!(receipt.dropped, 0);
            accepted += receipt.accepted;
        }
        assert_eq!(accepted, MAX_RECORDED_EVENTS);

        let over = service
            .record_events(RecordEvents {
                recording_id,
                events: capacity_events(last_kept + 1, last_kept + 5),
            })
            .expect("capacity no longer kills the capture");
        assert_eq!((over.accepted, over.dropped, over.duplicates), (0, 5, 0));

        let replay = service
            .record_events(RecordEvents {
                recording_id,
                events: capacity_events(last_kept + 1, last_kept + 5),
            })
            .expect("replay of dropped events");
        assert_eq!((replay.accepted, replay.dropped, replay.duplicates), (0, 0, 5));

        let next = service
            .record_events(RecordEvents {
                recording_id,
                events: capacity_events(last_kept + 6, last_kept + 6),
            })
            .expect("capture continues after capacity");
        assert_eq!((next.accepted, next.dropped), (0, 1));
        let gap = service.record_events(RecordEvents {
            recording_id,
            events: capacity_events(last_kept + 8, last_kept + 8),
        });
        assert_eq!(gap.expect_err("sequence gap stays a conflict").kind(), PortErrorKind::Conflict);

        let mut finish = FinishRecording::without_digest(recording_id, last_kept + 6);
        finish.event_digest = vec![7; 32];
        finish.drop_counts_by_priority.insert(10, 3);
        let receipt = service.finish_recording(finish.clone()).expect("finish");
        assert_eq!(receipt.completion, RecordingCompletion::Partial);

        let finishes = port.finishes.lock().expect("finishes");
        assert_eq!(finishes.len(), 1);
        assert!(finishes[0].event_digest.is_empty(), "unverifiable digest is withheld");
        assert_eq!(finishes[0].final_recording_seq, last_kept + 6);
        // Each dropped event is counted under its own priority, added to the
        // adapter-reported count for that bucket (no reserved bucket).
        let mut expected_drops: BTreeMap<u32, u64> = [(10, 3)].into_iter().collect();
        for sequence in last_kept + 1..=last_kept + 6 {
            *expected_drops.entry(capacity_priority(sequence)).or_insert(0) += 1;
        }
        assert_eq!(expected_drops.len(), 3);
        assert_eq!(finishes[0].drop_counts_by_priority, expected_drops);
        assert_eq!(finishes[0].capacity_dropped_events, 6);
        drop(finishes);

        let sequences = persisted_sequences(&port);
        assert_eq!(sequences.len(), MAX_RECORDED_EVENTS);
        assert!(sequences.iter().copied().eq(2..=last_kept), "persisted prefix is contiguous");

        let replayed = service.finish_recording(finish).expect("exact finish replay");
        assert!(replayed.exact_replay);
        assert_eq!(replayed.completion, RecordingCompletion::Partial);
        let sealed = service.record_events(RecordEvents {
            recording_id,
            events: capacity_events(last_kept + 7, last_kept + 7),
        });
        assert_eq!(
            sealed.expect_err("dropped events are rejected after finish").kind(),
            PortErrorKind::Conflict
        );
    }

    #[test]
    fn one_batch_crossing_capacity_persists_the_prefix_and_counts_the_rest() {
        let port = Arc::new(FakePort::default());
        let service = service(Arc::clone(&port), SegmentPolicy::default());
        service.begin_recording(begin(wall(1))).expect("begin");
        let recording_id = begin(wall(1)).recording_id;
        let last_kept = 1 + MAX_RECORDED_EVENTS as u64;

        let receipt = service
            .record_events(RecordEvents {
                recording_id,
                events: capacity_events(2, last_kept + 13),
            })
            .expect("crossing batch");
        assert_eq!((receipt.accepted, receipt.dropped), (MAX_RECORDED_EVENTS, 13));
        service
            .finish_recording(FinishRecording::without_digest(recording_id, last_kept + 13))
            .expect("finish");
        assert!(persisted_sequences(&port).iter().copied().eq(2..=last_kept));
        let finishes = port.finishes.lock().expect("finishes");
        assert_eq!(finishes[0].capacity_dropped_events, 13);
        assert_eq!(finishes[0].drop_counts_by_priority.values().sum::<u64>(), 13);
        assert_eq!(finishes[0].drop_counts_by_priority.len(), 3);
    }

    #[test]
    fn declared_finish_gap_flushes_and_seals_as_partial() {
        let port = Arc::new(FakePort::default());
        let service = service(Arc::clone(&port), SegmentPolicy::default());
        service.begin_recording(begin(wall(1))).expect("begin");
        let recording_id = begin(wall(1)).recording_id;
        service
            .record_events(RecordEvents { recording_id, events: vec![event(2, 0, 2)] })
            .expect("event");
        let finished = service
            .finish_recording(FinishRecording::without_digest(recording_id, 3))
            .expect("declared finish gap persists terminal evidence");
        assert_eq!(finished.persisted_segments, 1);
        assert_eq!(finished.completion, RecordingCompletion::Partial);
        assert!(!port.snapshot().segments.is_empty());
        let conflicting =
            service.finish_recording(FinishRecording::without_digest(recording_id, 2));
        assert_eq!(
            conflicting.expect_err("finish evidence is immutable").kind(),
            PortErrorKind::Conflict
        );
    }

    #[test]
    fn ambiguous_port_failure_retains_and_retries_the_same_segment_request() {
        let port = Arc::new(FakePort::default());
        port.fail_next_segment_after_record.store(true, Ordering::SeqCst);
        let policy = SegmentPolicy::new(1, DEFAULT_SEGMENT_EVENT_BYTES, 1).expect("policy");
        let service = service(Arc::clone(&port), policy);
        service.begin_recording(begin(wall(1))).expect("begin");
        let recording_id = begin(wall(1)).recording_id;
        let original = event(2, 5, 0xaa);

        let failed =
            service.record_events(RecordEvents { recording_id, events: vec![original.clone()] });
        assert_eq!(failed.expect_err("injected failure").kind(), PortErrorKind::Transport);

        let replay = service
            .record_events(RecordEvents { recording_id, events: vec![original] })
            .expect("pending retry then duplicate replay");
        assert_eq!(replay.persisted_segments, 1);
        assert_eq!(replay.duplicates, 1);
        let snapshot = port.snapshot();
        assert_eq!(snapshot.segments.len(), 2);
        assert_eq!(snapshot.segments[0].segment_ordinal, snapshot.segments[1].segment_ordinal);
        assert_eq!(snapshot.segments[0].events, snapshot.segments[1].events);
    }

    #[test]
    fn rejected_finish_does_not_poison_corrected_retry_after_pending_segment_retry() {
        let port = Arc::new(FakePort::default());
        port.fail_next_segment_after_record.store(true, Ordering::SeqCst);
        let policy = SegmentPolicy::new(1, DEFAULT_SEGMENT_EVENT_BYTES, 1).expect("policy");
        let service = service(Arc::clone(&port), policy);
        service.begin_recording(begin(wall(1))).expect("begin");
        let recording_id = begin(wall(1)).recording_id;
        let event = event(2, 1, 0xaa);

        let staged =
            service.record_events(RecordEvents { recording_id, events: vec![event.clone()] });
        assert_eq!(
            staged.expect_err("injected ambiguous segment failure").kind(),
            PortErrorKind::Transport
        );

        let mut malformed = FinishRecording::without_digest(recording_id, 2);
        malformed.unsupported_capability_codes = (0..65).map(|_| "optional".to_string()).collect();
        assert_eq!(
            service.finish_recording(malformed).expect_err("bounded finish validation").kind(),
            PortErrorKind::Validation,
        );

        let corrected = service
            .finish_recording(FinishRecording::without_digest(recording_id, 2))
            .expect("corrected finish remains admissible");
        assert_eq!(corrected.completion, RecordingCompletion::Partial);
        let snapshot = port.snapshot();
        assert_eq!(snapshot.segments.len(), 2);
        assert_eq!(snapshot.segments[0].events, snapshot.segments[1].events);
    }

    #[test]
    fn finish_flushes_without_allowing_new_events_or_claiming_a_terminal_state() {
        let port = Arc::new(FakePort::default());
        let service = service(Arc::clone(&port), SegmentPolicy::default());
        service.begin_recording(begin(wall(1))).expect("begin");
        let recording_id = begin(wall(1)).recording_id;
        let original = event(2, 1, 0xaa);
        service
            .record_events(RecordEvents { recording_id, events: vec![original.clone()] })
            .expect("event");
        let finish = service
            .finish_recording(FinishRecording::without_digest(recording_id, 2))
            .expect("finish");
        assert_eq!(finish.persisted_segments, 1);
        assert!(!finish.exact_replay);
        let replay = service
            .finish_recording(FinishRecording::without_digest(recording_id, 2))
            .expect("finish replay");
        assert!(replay.exact_replay);

        let duplicate = service
            .record_events(RecordEvents { recording_id, events: vec![original] })
            .expect("exact duplicate after finish");
        assert_eq!(duplicate.duplicates, 1);
        let new_event =
            service.record_events(RecordEvents { recording_id, events: vec![event(3, 2, 0xbb)] });
        assert_eq!(new_event.expect_err("new event rejected").kind(), PortErrorKind::Conflict);
    }
}
