//! Recording assembler validator.
//!
//! The validator is the single seam where XTP-Agent wire payloads
//! (`RecordingStarted`, `EventBatch`, `RecordingFinished`) meet the
//! per-recording sequencing and lifecycle contract documented in
//! `03-program-design.md` §5.3 and `03a-domain-and-storage.md` §4.
//! It is framework-neutral, asynchronous-free, and IO-free: it never
//! performs storage writes, never opens a network handle, and never
//! depends on the daemon loop. The domain crate stays protocol-free
//! by design; this crate is the only place where the generated wire
//! types and the typed recording lifecycle are combined.
//!
//! Responsibilities:
//!
//! - Maintain a map keyed by validated [`RecordingId`] so multiple
//!   recording IDs interleave independently inside one validator.
//!   Every accepted entry — including [`RecordingLifecycle::Finalizing`]
//!   — and its retained event digests remain in the map for the
//!   lifetime of the [`IngestValidator`] because this slice does not
//!   expose a drain or removal API.
//! - Reject malformed wire [`RecordingId`]s (anything other than
//!   exactly 16 bytes) before mutating state.
//! - Enforce `recording_seq == 1` for the structural start marker and
//!   retain a cloned `RecordingStarted` so identical retries remain
//!   idempotent via `PartialEq` even after the recording has
//!   transitioned to [`RecordingLifecycle::Finalizing`].
//! - Reject duplicate events whose deterministic payload digest
//!   differs from the one stored at first acceptance as the
//!   session-fatal [`IngestError::ReplayPayloadMismatch`].
//! - Treat strict ascending `recording_seq` inside an `EventBatch`
//!   as a pre-flight requirement; the entire batch is rejected before
//!   any event is retained.
//! - Accept a mixed prefix of already-known duplicates followed by a
//!   strictly contiguous run of new events atomically so a single
//!   retransmission window can drain cleanly.
//! - Surface a forward `recording_seq` gap as
//!   [`IngestError::RetransmissionNeeded`] without mutating state and
//!   without buffering out-of-order events.
//! - Transition a recording to [`RecordingLifecycle::Finalizing`] only
//!   when the `RecordingFinished.final_recording_seq` matches the
//!   validator's highest contiguous value. The retained event digests
//!   stay available for replay after finalization for the lifetime of
//!   the validator.
//! - Enforce active recording and per-recording event capacities as
//!   typed, no-mutation rejections.
//!
//! What the validator does **not** do:
//!
//! - It does not decode protobuf, allocate sockets, own durable
//!   storage, drain finalizing entries, or release retained digests.
//! - It does not depend on `xtrace-application`, `xtrace-store`, the
//!   daemon loop, the CLI, or any language-pack runtime.
//! - It does not apply `DropNotice` handling or priority-based
//!   degradation. Those policies live downstream in the durability
//!   and daemon layers; this crate only surfaces typed capacity
//!   reasons so callers can decide how to react.
//! - It does not expose a general canonical protobuf digest helper.
//!   The private event digest combines a private BLAKE3 type-domain
//!   prefix with the prost encoding of [`RecordingEvent`]; it is
//!   intentionally narrow so callers cannot mistake it for a stable
//!   cross-crate canonicalization contract.
//!
//! [`RecordingEvent`]: xtrace_protocol::generated::agent::RecordingEvent

use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroUsize;

use blake3::Hasher;
use prost::Message as _;
use uuid::Uuid;
use xtrace_domain::{CaptureBudget, CaptureMode, RecordingId};
use xtrace_protocol::generated::agent::{
    EventBatch, RecordingEvent, RecordingEventKind, RecordingFinished, RecordingStarted,
};

use crate::error::IngestError;
use crate::event_rules::{
    event_preview_bytes, normalize_started, validate_event, validate_finished,
};

/// Legacy S0b per-recording event budget, kept as the cap [`IngestConfig::new`] applies until the
/// daemon and application layers adopt the mode-derived caps (`CaptureMode::event_cap`) together
/// (contracts RC-04, lane C-surface). Use [`IngestConfig::mode_derived`] for the new behaviour.
pub const DEFAULT_MAX_EVENTS_PER_RECORDING: usize = 2048;

/// BLAKE3 type-domain prefix for the per-event payload digest.
///
/// The prefix is private to this module so the digest cannot collide
/// with any other hash produced by the X-trace stack. It is not
/// versioned as a public contract: the helper that consumes it is
/// private, so future schema changes do not need a public bump.
const EVENT_DIGEST_DOMAIN: &[u8] = b"xtrace.ingest.event.v1";

/// Visible lifecycle state of a recording under assembly.
///
/// The validator tracks two states. Finalizing means the structural
/// end marker has been accepted and the recording is sealed against
/// further event arrivals; only an exact replay of already-accepted
/// events remains valid input. The domain's terminal
/// `RecordingState::Complete` / `Partial` / `Invalid` variants live
/// downstream and are out of scope for this boundary.
///
/// Finalizing entries and their retained event digests stay in the
/// validator's map for the validator's lifetime; this crate does not
/// evict, drop, or otherwise reclaim them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordingLifecycle {
    /// `RecordingStarted` accepted; events still arriving.
    Recording,
    /// `RecordingFinished` accepted; only duplicate events permitted.
    Finalizing,
}

/// Configuration for an [`IngestValidator`].
///
/// `max_active_recordings` is mandatory and never defaulted: the
/// production caller is responsible for sizing the active-recording
/// budget against the per-recording assembly capacity table in
/// `03-program-design.md` §6. The per-recording event cap is derived from the recording's
/// effective [`CaptureMode`] unless `event_cap_override` is set; [`IngestConfig::new`] sets the
/// legacy 2,048 override, [`IngestConfig::mode_derived`] leaves it unset.
#[derive(Clone, Debug)]
pub struct IngestConfig {
    /// Maximum number of recordings the validator will track
    /// concurrently (`Recording` plus `Finalizing`).
    pub max_active_recordings: NonZeroUsize,
    /// Overrides the mode-derived per-recording event cap. Further new events
    /// are dropped and counted by priority instead of failing the capture.
    pub event_cap_override: Option<NonZeroUsize>,
    /// Whether the daemon audit redactor runs on every event before storage. While `false`, any
    /// event carrying `bindings` is rejected with [`IngestError::BindingsNotAcceptedYet`].
    pub bindings_audit_active: bool,
}

impl IngestConfig {
    /// Builds a configuration with the legacy 2,048-event budget for every mode.
    ///
    /// `max_active_recordings` is supplied by the caller because the
    /// active budget depends on the surrounding daemon topology. The legacy budget falls back to
    /// [`NonZeroUsize::MIN`] only if a future edit changes
    /// [`DEFAULT_MAX_EVENTS_PER_RECORDING`] to `0`, so this constructor never panics.
    #[must_use]
    pub fn new(max_active_recordings: NonZeroUsize) -> Self {
        let legacy =
            NonZeroUsize::new(DEFAULT_MAX_EVENTS_PER_RECORDING).unwrap_or(NonZeroUsize::MIN);
        Self {
            max_active_recordings,
            event_cap_override: Some(legacy),
            bindings_audit_active: false,
        }
    }

    /// Builds a configuration whose per-recording cap follows the effective capture mode
    /// (16,384 standard, 131,072 focused).
    #[must_use]
    pub const fn mode_derived(max_active_recordings: NonZeroUsize) -> Self {
        Self { max_active_recordings, event_cap_override: None, bindings_audit_active: false }
    }

    /// Overrides the per-recording event budget. Intended for tests
    /// that need to exercise the [`IngestError::EventCapacityReached`]
    /// boundary without sending the production event budget.
    #[must_use]
    pub const fn with_limit(mut self, max_events: NonZeroUsize) -> Self {
        self.event_cap_override = Some(max_events);
        self
    }

    /// Declares that the daemon audit redactor runs on every event before storage, which lets
    /// events carrying `bindings` through validation.
    #[must_use]
    pub const fn with_bindings_audit_active(mut self) -> Self {
        self.bindings_audit_active = true;
        self
    }

    /// The per-recording event cap in force for `mode`.
    #[must_use]
    pub fn event_cap(&self, mode: CaptureMode) -> usize {
        self.event_cap_override.map_or_else(|| mode.event_cap(), NonZeroUsize::get)
    }
}

/// Successful outcome of a single wire payload validation.
///
/// The enum carries no error variants: every failure is reported
/// through [`IngestError`] so the success side stays free of
/// `XTR-*` reason codes and matches the public error contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Acceptance {
    /// `RecordingStarted` accepted for the first time.
    Started,
    /// `RecordingStarted` accepted as an idempotent retry whose
    /// fields compare equal under `PartialEq` against the cloned
    /// start marker already on file. The comparison is the
    /// field-by-field equality that prost derives for the generated
    /// struct, so two adapters that encode the same start fields
    /// produce the same verdict regardless of internal map
    /// iteration order. Returned even after the recording has
    /// transitioned to [`RecordingLifecycle::Finalizing`] so an
    /// adapter can recover a dropped ACK without poisoning the
    /// session.
    StartedRetry,
    /// `EventBatch` accepted. `accepted` counts newly retained
    /// events; `duplicates` counts events that matched an already
    /// retained sequence and payload digest. `highest_contiguous` is
    /// the new highest contiguous `recording_seq` after the batch
    /// was committed; for an empty batch it is the recording's
    /// current value without mutation.
    Events {
        /// Number of new contiguous events retained from the batch.
        accepted: usize,
        /// Number of events that matched an already retained
        /// sequence and payload digest.
        duplicates: usize,
        /// Highest contiguous `recording_seq` after the batch.
        highest_contiguous: u64,
    },
    /// `RecordingFinished` accepted; the recording has transitioned
    /// from [`RecordingLifecycle::Recording`] to
    /// [`RecordingLifecycle::Finalizing`].
    Finalizing,
    /// `RecordingFinished` accepted as an idempotent retry whose
    /// fields compare equal under `PartialEq` against the cloned
    /// finish marker already on file. The comparison is the
    /// field-by-field equality that prost derives for the generated
    /// struct.
    FinishedRetry,
}

/// Per-recording private state retained by the validator.
#[derive(Debug)]
struct RecordingState {
    /// Effective capture mode, computed by the caller from the armed mode and the claimed policy
    /// id; it selects the event cap and the per-mode event rules.
    mode: CaptureMode,
    /// Cloned copy of the first accepted `RecordingStarted`.
    /// Identity-conflict detection compares a retry against this
    /// struct via `PartialEq`, which prost derives field-by-field
    /// and is therefore independent of any internal map iteration
    /// order.
    started: RecordingStarted,
    /// Cloned copy of the first accepted `RecordingFinished`, when
    /// set marks the recording as
    /// [`RecordingLifecycle::Finalizing`].
    finished: Option<RecordingFinished>,
    /// Highest contiguous `recording_seq` retained by the validator,
    /// equal to 1 immediately after a successful `RecordingStarted`
    /// (the structural marker counts even though it is not stored
    /// as an event digest) and never decreases.
    highest_contiguous: u64,
    /// Deterministic typed digest of every accepted `RecordingEvent`,
    /// keyed by `recording_seq`. The structural start marker is not
    /// stored here. Digests stay in the map after finalization for
    /// the lifetime of the validator so exact replays remain
    /// idempotent; this crate does not evict them.
    event_digests: HashMap<u64, [u8; 32]>,
    /// Lowest `recording_seq` dropped at the event capacity, if any. Every
    /// sequence from here up to `highest_contiguous` was counted but its
    /// digest was not retained, so a replay of it is a duplicate.
    first_dropped_seq: Option<u64>,
    /// Events dropped at the event capacity, counted under their own
    /// priority. At most [`MAX_DROP_PRIORITY_BUCKETS`] distinct priorities.
    capacity_dropped_by_priority: BTreeMap<u32, u64>,
    /// Running preview bytes of every retained event (CaptureBudget `max_value_bytes_per_recording`).
    value_bytes: u64,
    /// Running count of retained `LINE_CURSOR` events (CaptureBudget `max_line_events`).
    line_events: u32,
}

/// Upper bound on distinct priorities tracked for capacity drops of one
/// recording, so drop accounting is as bounded as the digest table.
pub const MAX_DROP_PRIORITY_BUCKETS: usize = 64;

/// Decodes the wire `recording_id` bytes into a domain [`RecordingId`].
///
/// The wire type carries the identifier as an opaque byte string, but
/// every domain `RecordingId` is a 16-byte UUIDv7. Any other length
/// is rejected up front so the validator never has to reason about
/// truncated or padded identifiers inside its state machine.
fn recording_id_from_bytes(bytes: &[u8]) -> Result<RecordingId, IngestError> {
    if bytes.len() != 16 {
        return Err(IngestError::InvalidRecordingId { got: bytes.len() });
    }
    let uuid = Uuid::from_slice(bytes)
        .map_err(|_| IngestError::InvalidRecordingId { got: bytes.len() })?;
    Ok(RecordingId::from_uuid(uuid))
}

/// Computes the private deterministic digest of a single
/// [`RecordingEvent`].
///
/// The digest combines a private BLAKE3 type-domain prefix with the
/// prost encoding of the event so two adapters that encode the same
/// event field-by-field produce the same digest. The helper is
/// intentionally narrow: [`RecordingEvent`] has no protobuf `map`
/// fields, so its prost encoding is deterministic, and the prefix
/// makes the digest safe to compare across crate versions. The
/// helper is private so callers cannot mistake it for a stable
/// cross-crate canonicalization contract.
fn event_digest(event: &RecordingEvent) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(EVENT_DIGEST_DOMAIN);
    hasher.update(&event.encode_to_vec());
    let mut out = [0u8; 32];
    out.copy_from_slice(hasher.finalize().as_bytes());
    out
}

/// Per-recording sequence, lifecycle, and idempotency validator.
///
/// Constructed from an [`IngestConfig`] and grown by accepting
/// `RecordingStarted`, `EventBatch`, and `RecordingFinished` payloads
/// in the order the adapter emits them. Multiple recording IDs
/// interleave independently inside one validator; the validator is
/// not safe to share across threads without external synchronization.
#[derive(Debug)]
pub struct IngestValidator {
    config: IngestConfig,
    recordings: HashMap<RecordingId, RecordingState>,
}

impl IngestValidator {
    /// Builds a fresh validator with the supplied configuration.
    #[must_use]
    pub fn new(config: IngestConfig) -> Self {
        Self { config, recordings: HashMap::new() }
    }

    /// Returns the configuration the validator was built with.
    #[must_use]
    pub fn config(&self) -> &IngestConfig {
        &self.config
    }

    /// Returns the number of recordings the validator is currently
    /// tracking, counting both [`RecordingLifecycle::Recording`] and
    /// [`RecordingLifecycle::Finalizing`] entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.recordings.len()
    }

    /// Returns `true` when the validator is tracking no recordings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.recordings.is_empty()
    }

    /// Returns the visible lifecycle of the supplied recording, or
    /// `None` when the validator has no entry for it.
    #[must_use]
    pub fn lifecycle(&self, id: RecordingId) -> Option<RecordingLifecycle> {
        self.recordings.get(&id).map(|state| {
            if state.finished.is_some() {
                RecordingLifecycle::Finalizing
            } else {
                RecordingLifecycle::Recording
            }
        })
    }

    /// Returns the highest contiguous `recording_seq` the validator
    /// holds for the supplied recording, or `None` when the
    /// recording is unknown. The returned value is 1 immediately
    /// after a successful `RecordingStarted`.
    #[must_use]
    pub fn highest_contiguous_seq(&self, id: RecordingId) -> Option<u64> {
        self.recordings.get(&id).map(|state| state.highest_contiguous)
    }

    /// Returns the events dropped at the per-recording event capacity,
    /// counted under their own priority, or `None` when the recording is
    /// unknown. Empty when nothing was dropped.
    #[must_use]
    pub fn capacity_drops(&self, id: RecordingId) -> Option<&BTreeMap<u32, u64>> {
        self.recordings.get(&id).map(|state| &state.capacity_dropped_by_priority)
    }

    /// Accepts a [`RecordingStarted`] payload.
    ///
    /// The `recording_id` must be exactly 16 bytes; `recording_seq`
    /// must be `1`. An identical retry returns
    /// [`Acceptance::StartedRetry`] even after the recording has
    /// transitioned to [`RecordingLifecycle::Finalizing`]. A second
    /// start with the same recording identifier but different
    /// `PartialEq` view is rejected with the session-fatal
    /// [`IngestError::StartedConflict`]; the recording is left
    /// untouched so the downstream supervisor can quarantine the
    /// session without losing evidence.
    ///
    /// # Errors
    ///
    /// Returns [`IngestError::InvalidRecordingId`] when the wire
    /// `recording_id` is not 16 bytes long,
    /// [`IngestError::InvalidStartSeq`] when `recording_seq != 1`,
    /// [`IngestError::ActiveCapacityReached`] when accepting the
    /// recording would exceed the configured active-recording
    /// budget, or [`IngestError::StartedConflict`] when the recording
    /// identifier is already known and the cloned start differs
    /// under `PartialEq`.
    pub fn accept_started(
        &mut self,
        started: &RecordingStarted,
        mode: CaptureMode,
    ) -> Result<Acceptance, IngestError> {
        // An invalid `exercise_item_id` is cleared, never stored, so retries compare the
        // normalized form.
        let started = &normalize_started(started);
        let id = recording_id_from_bytes(&started.recording_id)?;
        if started.recording_seq != 1 {
            return Err(IngestError::InvalidStartSeq {
                recording_id: id,
                got: started.recording_seq,
            });
        }

        if let Some(state) = self.recordings.get(&id) {
            if &state.started == started {
                return Ok(Acceptance::StartedRetry);
            }
            return Err(IngestError::StartedConflict(id));
        }

        if self.recordings.len() >= self.config.max_active_recordings.get() {
            return Err(IngestError::ActiveCapacityReached {
                limit: self.config.max_active_recordings,
            });
        }

        self.recordings.insert(
            id,
            RecordingState {
                mode,
                started: started.clone(),
                finished: None,
                highest_contiguous: 1,
                event_digests: HashMap::new(),
                first_dropped_seq: None,
                capacity_dropped_by_priority: BTreeMap::new(),
                value_bytes: 0,
                line_events: 0,
            },
        );
        Ok(Acceptance::Started)
    }

    /// Accepts an [`EventBatch`] payload.
    ///
    /// The batch is rejected as a whole when the internal
    /// `recording_seq` values are not strictly ascending, when an
    /// event creates a forward gap relative to the recording's
    /// highest contiguous value, or when accepting the batch would
    /// exceed the configured event budget. State is never mutated
    /// until the entire batch has been pre-flighted.
    ///
    /// An empty batch is a successful no-op only when the recording
    /// is known; it returns the current `highest_contiguous` for
    /// that recording without mutation. An empty batch for an
    /// unknown recording is rejected with
    /// [`IngestError::UnknownRecording`] so the adapter must
    /// retransmit the structural start marker before any further
    /// event traffic. A duplicate event whose deterministic
    /// payload digest differs from the digest stored at first
    /// acceptance is rejected with the session-fatal
    /// [`IngestError::ReplayPayloadMismatch`].
    ///
    /// The preflight compares each `recording_seq` directly against
    /// a local `candidate_highest` watermark that begins at the
    /// recording's current `highest_contiguous` and is advanced by
    /// assignment rather than checked arithmetic. `seq <=
    /// candidate_highest` is a duplicate, `seq ==
    /// candidate_highest + 1` is a new contiguous event, and `seq >
    /// candidate_highest + 1` is a forward gap. Because the new
    /// branch is only reached when `seq > candidate_highest`, the
    /// `+ 1` is guaranteed safe and no checked arithmetic is ever
    /// performed; an exact replay at `u64::MAX` and a final
    /// contiguous event at `u64::MAX` from `u64::MAX - 1` are both
    /// accepted without overflow.
    ///
    /// # Errors
    ///
    /// Returns [`IngestError::InvalidRecordingId`],
    /// [`IngestError::NonMonotonicBatch`],
    /// [`IngestError::UnknownRecording`],
    /// [`IngestError::ReplayPayloadMismatch`],
    /// [`IngestError::RetransmissionNeeded`],
    /// [`IngestError::EventAfterFinalization`], or
    /// [`IngestError::EventCapacityReached`] (only when the capacity-drop
    /// ledger itself would exceed its bounded priority buckets).
    pub fn accept_events(&mut self, batch: &EventBatch) -> Result<Acceptance, IngestError> {
        let id = recording_id_from_bytes(&batch.recording_id)?;

        if batch.events.is_empty() {
            return match self.recordings.get_mut(&id) {
                Some(state) => Ok(Acceptance::Events {
                    accepted: 0,
                    duplicates: 0,
                    highest_contiguous: state.highest_contiguous,
                }),
                None => Err(IngestError::UnknownRecording(id)),
            };
        }

        for pair in batch.events.windows(2) {
            let prev = pair[0].recording_seq;
            let got = pair[1].recording_seq;
            if got <= prev {
                return Err(IngestError::NonMonotonicBatch { recording_id: id, prev, got });
            }
        }

        let state = self.recordings.get_mut(&id).ok_or(IngestError::UnknownRecording(id))?;

        let is_finalizing = state.finished.is_some();
        let event_digest_count = state.event_digests.len();
        let mode = state.mode;
        let audit_active = self.config.bindings_audit_active;
        let max_events = self.config.event_cap(mode);

        let mut new_count: usize = 0;
        let mut duplicates: usize = 0;
        let mut candidate_highest: u64 = state.highest_contiguous;
        let mut pending: Vec<(u64, [u8; 32])> = Vec::with_capacity(batch.events.len());
        let budget = CaptureBudget::for_mode(mode);
        let mut pending_value_bytes: u64 = 0;
        let mut pending_lines: u32 = 0;
        let mut drops = state.capacity_dropped_by_priority.clone();
        let mut first_dropped = state.first_dropped_seq;

        // Validate every event before any state changes, so one bad event rejects the whole
        // batch and the adapter resends a corrected event at the same sequence.
        for event in &batch.events {
            validate_event(event, mode, audit_active)?;
        }

        for event in &batch.events {
            let seq = event.recording_seq;
            let digest = event_digest(event);

            if seq <= candidate_highest {
                match state.event_digests.get(&seq) {
                    Some(stored) if *stored == digest => {
                        duplicates += 1;
                    }
                    // A sequence dropped at capacity kept no digest; its
                    // replay is a duplicate of something already counted.
                    None if state.first_dropped_seq.is_some_and(|first| seq >= first) => {
                        duplicates += 1;
                    }
                    _ => {
                        return Err(IngestError::ReplayPayloadMismatch {
                            recording_id: id,
                            recording_seq: seq,
                        });
                    }
                }
                continue;
            }

            // `seq > candidate_highest` so `candidate_highest <
            // u64::MAX` and `candidate_highest + 1` cannot overflow.
            // The next contiguous slot is therefore safe to compute
            // and the gap error path can report it without checked
            // arithmetic.
            if seq == candidate_highest + 1 {
                if is_finalizing {
                    return Err(IngestError::EventAfterFinalization {
                        recording_id: id,
                        recording_seq: seq,
                    });
                }
                // Past the retained-digest budget the event is dropped:
                // counted under its own priority, advancing the
                // watermark, but never retained. Only a drop ledger that
                // itself would outgrow its bound is refused; that check
                // happens before mutation so the batch is atomic.
                // The per-recording budgets (CaptureBudget) are enforced here as well: an event
                // that would push the running preview-byte or line-event total over its budget
                // is dropped and counted under its own priority exactly like a capacity drop.
                let event_bytes = event_preview_bytes(event);
                let is_line = event.kind == RecordingEventKind::LineCursor as i32;
                let over_value_budget = state
                    .value_bytes
                    .saturating_add(pending_value_bytes)
                    .saturating_add(event_bytes)
                    > budget.max_value_bytes_per_recording;
                let over_line_budget = is_line
                    && state.line_events.saturating_add(pending_lines).saturating_add(1)
                        > budget.max_line_events;
                if event_digest_count.saturating_add(new_count).saturating_add(1) > max_events
                    || over_value_budget
                    || over_line_budget
                {
                    if !drops.contains_key(&event.priority)
                        && drops.len() >= MAX_DROP_PRIORITY_BUCKETS
                    {
                        return Err(IngestError::EventCapacityReached {
                            recording_id: id,
                            limit: NonZeroUsize::new(max_events).unwrap_or(NonZeroUsize::MIN),
                        });
                    }
                    let bucket = drops.entry(event.priority).or_insert(0);
                    *bucket = bucket.saturating_add(1);
                    first_dropped.get_or_insert(seq);
                    candidate_highest = seq;
                    continue;
                }
                pending.push((seq, digest));
                pending_value_bytes = pending_value_bytes.saturating_add(event_bytes);
                pending_lines = pending_lines.saturating_add(u32::from(is_line));
                new_count += 1;
                // Advance the local watermark so a contiguous run
                // such as `[3, 4, 5]` is matched against the latest
                // candidate rather than the initial value. The
                // entry condition `seq > candidate_highest` proves
                // `candidate_highest < u64::MAX`, so the subsequent
                // `candidate_highest + 1` is overflow safe; a final
                // contiguous event at `u64::MAX` therefore requires
                // no checked arithmetic.
                candidate_highest = seq;
                continue;
            }

            // `seq > candidate_highest + 1` is a forward gap, but a
            // finalized recording rejects any new event outright
            // before reporting a retransmission hint so the adapter
            // gets the right reason for a sealed recording.
            if is_finalizing {
                return Err(IngestError::EventAfterFinalization {
                    recording_id: id,
                    recording_seq: seq,
                });
            }
            return Err(IngestError::RetransmissionNeeded {
                recording_id: id,
                expected: candidate_highest + 1,
                received: seq,
            });
        }

        // Commit only after the preflight has accepted the entire
        // batch. `candidate_highest` already reflects the watermark
        // of every accepted new event, so no further recomputation
        // is needed.
        for (seq, digest) in pending {
            state.event_digests.insert(seq, digest);
        }
        state.value_bytes = state.value_bytes.saturating_add(pending_value_bytes);
        state.line_events = state.line_events.saturating_add(pending_lines);
        state.highest_contiguous = candidate_highest;
        state.capacity_dropped_by_priority = drops;
        state.first_dropped_seq = first_dropped;

        Ok(Acceptance::Events {
            accepted: new_count,
            duplicates,
            highest_contiguous: state.highest_contiguous,
        })
    }

    /// Accepts a [`RecordingFinished`] payload.
    ///
    /// The recording must already be known to the validator. The
    /// `final_recording_seq` must equal the recording's current
    /// highest contiguous value. An identical retry returns
    /// [`Acceptance::FinishedRetry`]; a second finish with the same
    /// recording identifier but different `PartialEq` view is
    /// rejected with the session-fatal
    /// [`IngestError::FinishedConflict`].
    ///
    /// # Errors
    ///
    /// Returns [`IngestError::InvalidRecordingId`],
    /// [`IngestError::UnknownRecording`],
    /// [`IngestError::FinishSeqMismatch`], or
    /// [`IngestError::FinishedConflict`].
    pub fn accept_finished(
        &mut self,
        finished: &RecordingFinished,
    ) -> Result<Acceptance, IngestError> {
        let id = recording_id_from_bytes(&finished.recording_id)?;

        let state = self.recordings.get_mut(&id).ok_or(IngestError::UnknownRecording(id))?;

        validate_finished(finished, id)?;

        if let Some(existing) = &state.finished {
            if existing == finished {
                return Ok(Acceptance::FinishedRetry);
            }
            return Err(IngestError::FinishedConflict(id));
        }

        if finished.final_recording_seq != state.highest_contiguous {
            return Err(IngestError::FinishSeqMismatch {
                recording_id: id,
                expected: state.highest_contiguous,
                got: finished.final_recording_seq,
            });
        }

        state.finished = Some(finished.clone());
        Ok(Acceptance::Finalizing)
    }
}

/// Test-only injection helper.
///
/// Reaches a private `recording_seq` near `u64::MAX` through a
/// cfg-gated back door so a unit test can prove that the validator
/// accepts an exact replay at `u64::MAX` and a final contiguous
/// event at `u64::MAX` from `u64::MAX - 1` without sending the full
/// 2,048-event default budget. The helper is not reachable from
/// production builds.
#[cfg(test)]
impl IngestValidator {
    pub(crate) fn _test_inject_state(
        &mut self,
        id: RecordingId,
        started: RecordingStarted,
        highest_contiguous: u64,
        event_digests: HashMap<u64, [u8; 32]>,
    ) {
        self.recordings.insert(
            id,
            RecordingState {
                mode: CaptureMode::Standard,
                started,
                finished: None,
                highest_contiguous,
                event_digests,
                first_dropped_seq: None,
                capacity_dropped_by_priority: BTreeMap::new(),
                value_bytes: 0,
                line_events: 0,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    //! Colocated unit tests for the recording assembler boundary.
    //!
    //! Each test exercises a single behavioural clause from the
    //! Slice 1C.2 acceptance list. Helpers at the top build the
    //! generated wire payloads and the UUID-16 recording identifier
    //! so the test bodies stay focused on the validator contract.

    use std::collections::HashMap;
    use std::num::NonZeroUsize;

    use prost::bytes::Bytes;
    use xtrace_domain::RecordingId;
    use xtrace_domain::ids::Id as _;
    use xtrace_protocol::generated::agent::{
        EventBatch, RecordingEvent, RecordingFinished, RecordingStarted,
    };

    use super::{
        Acceptance, DEFAULT_MAX_EVENTS_PER_RECORDING, IngestConfig, IngestError, IngestValidator,
        RecordingLifecycle, event_digest,
    };
    use xtrace_domain::CaptureMode;

    fn rid() -> RecordingId {
        RecordingId::new()
    }

    fn rid_bytes(id: RecordingId) -> Bytes {
        Bytes::copy_from_slice(id.as_uuid().as_bytes())
    }

    fn short_bytes() -> Bytes {
        Bytes::copy_from_slice(&[0xab_u8; 15])
    }

    fn long_bytes() -> Bytes {
        Bytes::copy_from_slice(&[0xcd_u8; 17])
    }

    fn started(id: RecordingId, method: &str) -> RecordingStarted {
        RecordingStarted {
            recording_id: rid_bytes(id),
            recording_seq: 1,
            method: method.to_string(),
            ..RecordingStarted::default()
        }
    }

    fn event(seq: u64, body: u8) -> RecordingEvent {
        RecordingEvent {
            recording_seq: seq,
            event_id: format!("e-{body}"),
            ..RecordingEvent::default()
        }
    }

    fn batch(id: RecordingId, events: Vec<RecordingEvent>) -> EventBatch {
        EventBatch { recording_id: rid_bytes(id), events }
    }

    fn empty_batch(id: RecordingId) -> EventBatch {
        EventBatch { recording_id: rid_bytes(id), events: Vec::new() }
    }

    fn finished(id: RecordingId, final_seq: u64) -> RecordingFinished {
        RecordingFinished {
            recording_id: rid_bytes(id),
            final_recording_seq: final_seq,
            ..RecordingFinished::default()
        }
    }

    fn finished_with_drop_counts(
        id: RecordingId,
        final_seq: u64,
        drop_counts: HashMap<u32, u64>,
    ) -> RecordingFinished {
        RecordingFinished {
            recording_id: rid_bytes(id),
            final_recording_seq: final_seq,
            drop_counts_by_priority: drop_counts,
            ..RecordingFinished::default()
        }
    }

    fn fresh_validator() -> IngestValidator {
        IngestValidator::new(IngestConfig::new(NonZeroUsize::new(8).unwrap()))
    }

    fn tight_validator(active: usize, events: usize) -> IngestValidator {
        IngestValidator::new(
            IngestConfig::new(NonZeroUsize::new(active).unwrap())
                .with_limit(NonZeroUsize::new(events).unwrap()),
        )
    }

    #[test]
    fn interleaved_two_recordings_happy_flow_ends_in_finalizing() {
        let mut validator = fresh_validator();
        let a = rid();
        let b = rid();

        assert_eq!(
            validator.accept_started(&started(a, "GET"), CaptureMode::Standard).unwrap(),
            Acceptance::Started
        );
        assert_eq!(validator.lifecycle(a), Some(RecordingLifecycle::Recording));
        assert_eq!(validator.highest_contiguous_seq(a), Some(1));
        assert_eq!(validator.len(), 1);

        assert_eq!(
            validator.accept_started(&started(b, "POST"), CaptureMode::Standard).unwrap(),
            Acceptance::Started
        );
        assert_eq!(validator.len(), 2);

        assert_eq!(
            validator.accept_events(&batch(a, vec![event(2, 0xaa), event(3, 0xab)])).unwrap(),
            Acceptance::Events { accepted: 2, duplicates: 0, highest_contiguous: 3 },
        );
        assert_eq!(
            validator.accept_events(&batch(b, vec![event(2, 0xba)])).unwrap(),
            Acceptance::Events { accepted: 1, duplicates: 0, highest_contiguous: 2 },
        );
        assert_eq!(
            validator.accept_events(&batch(a, vec![event(4, 0xac)])).unwrap(),
            Acceptance::Events { accepted: 1, duplicates: 0, highest_contiguous: 4 },
        );
        assert_eq!(
            validator.accept_events(&batch(b, vec![event(3, 0xbb), event(4, 0xbc)])).unwrap(),
            Acceptance::Events { accepted: 2, duplicates: 0, highest_contiguous: 4 },
        );

        assert_eq!(validator.accept_finished(&finished(a, 4)).unwrap(), Acceptance::Finalizing,);
        assert_eq!(validator.lifecycle(a), Some(RecordingLifecycle::Finalizing));
        assert_eq!(validator.highest_contiguous_seq(a), Some(4));
        assert_eq!(validator.lifecycle(b), Some(RecordingLifecycle::Recording));

        assert_eq!(validator.accept_finished(&finished(b, 4)).unwrap(), Acceptance::Finalizing,);
        assert_eq!(validator.lifecycle(b), Some(RecordingLifecycle::Finalizing));
        assert_eq!(validator.len(), 2);
        assert!(!validator.is_empty());
    }

    #[test]
    fn malformed_short_recording_id_is_rejected() {
        let mut validator = fresh_validator();
        let id = rid();
        let mut payload = started(id, "GET");
        payload.recording_id = short_bytes();
        let err = validator.accept_started(&payload, CaptureMode::Standard).unwrap_err();
        assert!(matches!(err, IngestError::InvalidRecordingId { got: 15 }));
        assert_eq!(validator.len(), 0);
        assert!(validator.is_empty());
    }

    #[test]
    fn malformed_long_recording_id_is_rejected() {
        let mut validator = fresh_validator();
        let id = rid();
        let mut payload = started(id, "GET");
        payload.recording_id = long_bytes();
        let err = validator.accept_started(&payload, CaptureMode::Standard).unwrap_err();
        assert!(matches!(err, IngestError::InvalidRecordingId { got: 17 }));
        assert_eq!(validator.len(), 0);
    }

    #[test]
    fn wrong_start_recording_seq_is_rejected() {
        let mut validator = fresh_validator();
        let id = rid();
        let mut payload = started(id, "GET");
        payload.recording_seq = 7;
        let err = validator.accept_started(&payload, CaptureMode::Standard).unwrap_err();
        assert!(matches!(
            err,
            IngestError::InvalidStartSeq { recording_id: rid_check, got: 7 } if rid_check == id,
        ));
        assert_eq!(validator.len(), 0);
    }

    #[test]
    fn non_monotonic_batch_is_rejected_atomically() {
        let mut validator = fresh_validator();
        let id = rid();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();

        // Dropping back from seq=3 to seq=2 fails the whole batch
        // and leaves the recording untouched.
        let err = validator
            .accept_events(&batch(id, vec![event(2, 1), event(3, 2), event(2, 3)]))
            .unwrap_err();
        assert!(matches!(
            err,
            IngestError::NonMonotonicBatch {
                recording_id: rid_check,
                prev: 3,
                got: 2,
            } if rid_check == id
        ));
        assert_eq!(validator.highest_contiguous_seq(id), Some(1));
        assert_eq!(validator.lifecycle(id), Some(RecordingLifecycle::Recording));

        // Two events with the same sequence also fail strictly.
        let err2 = validator.accept_events(&batch(id, vec![event(2, 1), event(2, 2)])).unwrap_err();
        assert!(matches!(err2, IngestError::NonMonotonicBatch { prev: 2, got: 2, .. }));
        assert_eq!(validator.highest_contiguous_seq(id), Some(1));
    }

    #[test]
    fn exact_event_replay_is_idempotent() {
        let mut validator = fresh_validator();
        let id = rid();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();

        let events = vec![event(2, 0xa1), event(3, 0xa2), event(4, 0xa3)];
        assert_eq!(
            validator.accept_events(&batch(id, events.clone())).unwrap(),
            Acceptance::Events { accepted: 3, duplicates: 0, highest_contiguous: 4 },
        );

        assert_eq!(
            validator.accept_events(&batch(id, events)).unwrap(),
            Acceptance::Events { accepted: 0, duplicates: 3, highest_contiguous: 4 },
        );
        assert_eq!(validator.highest_contiguous_seq(id), Some(4));
    }

    #[test]
    fn changed_replay_payload_is_session_fatal_and_does_not_mutate() {
        let mut validator = fresh_validator();
        let id = rid();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();

        validator.accept_events(&batch(id, vec![event(2, 0xa1), event(3, 0xa2)])).unwrap();
        assert_eq!(validator.highest_contiguous_seq(id), Some(3));

        // First event matches by sequence; the second carries a
        // different payload body, which is a session-fatal mismatch.
        let err =
            validator.accept_events(&batch(id, vec![event(2, 0xa1), event(3, 0xff)])).unwrap_err();
        assert!(err.is_session_fatal());
        assert!(matches!(
            err,
            IngestError::ReplayPayloadMismatch {
                recording_id: rid_check,
                recording_seq: 3,
            } if rid_check == id
        ));
        assert_eq!(validator.highest_contiguous_seq(id), Some(3));
    }

    #[test]
    fn forward_gap_is_reported_then_accepted_after_missing_batch() {
        let mut validator = fresh_validator();
        let id = rid();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();

        let err = validator.accept_events(&batch(id, vec![event(4, 0xa1)])).unwrap_err();
        assert!(matches!(
            err,
            IngestError::RetransmissionNeeded {
                recording_id: rid_check,
                expected: 2,
                received: 4,
            } if rid_check == id
        ));
        assert_eq!(validator.highest_contiguous_seq(id), Some(1));

        assert_eq!(
            validator.accept_events(&batch(id, vec![event(2, 0xb1), event(3, 0xb2)])).unwrap(),
            Acceptance::Events { accepted: 2, duplicates: 0, highest_contiguous: 3 },
        );
    }

    #[test]
    fn mixed_duplicate_prefix_and_new_suffix_accepted_atomically() {
        let mut validator = fresh_validator();
        let id = rid();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();

        assert_eq!(
            validator.accept_events(&batch(id, vec![event(2, 0xa1), event(3, 0xa2)])).unwrap(),
            Acceptance::Events { accepted: 2, duplicates: 0, highest_contiguous: 3 },
        );

        // seq=2 is a known duplicate, seq=3 is a known duplicate,
        // and seq=4 is the new contiguous extension.
        assert_eq!(
            validator
                .accept_events(&batch(id, vec![event(2, 0xa1), event(3, 0xa2), event(4, 0xa3)]))
                .unwrap(),
            Acceptance::Events { accepted: 1, duplicates: 2, highest_contiguous: 4 },
        );
        assert_eq!(validator.highest_contiguous_seq(id), Some(4));
    }

    #[test]
    fn finish_seq_mismatch_leaves_recording_untouched() {
        let mut validator = fresh_validator();
        let id = rid();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();
        validator.accept_events(&batch(id, vec![event(2, 0xa1)])).unwrap();
        let before = validator.highest_contiguous_seq(id);

        let err = validator.accept_finished(&finished(id, 99)).unwrap_err();
        assert!(matches!(
            err,
            IngestError::FinishSeqMismatch {
                recording_id: rid_check,
                expected: 2,
                got: 99,
            } if rid_check == id
        ));
        assert_eq!(validator.highest_contiguous_seq(id), before);
        assert_eq!(validator.lifecycle(id), Some(RecordingLifecycle::Recording));
    }

    #[test]
    fn exact_started_and_finished_retries_are_idempotent() {
        let mut validator = fresh_validator();
        let id = rid();

        assert_eq!(
            validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap(),
            Acceptance::Started
        );
        assert_eq!(
            validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap(),
            Acceptance::StartedRetry,
        );
        assert_eq!(
            validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap(),
            Acceptance::StartedRetry,
        );

        validator.accept_events(&batch(id, vec![event(2, 0xa1), event(3, 0xa2)])).unwrap();

        assert_eq!(validator.accept_finished(&finished(id, 3)).unwrap(), Acceptance::Finalizing,);
        assert_eq!(validator.accept_finished(&finished(id, 3)).unwrap(), Acceptance::FinishedRetry,);
        // After finalization the started retry is still idempotent,
        // never a duplicate-conflict return.
        assert_eq!(
            validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap(),
            Acceptance::StartedRetry,
        );
    }

    #[test]
    fn changed_started_or_finished_retries_are_session_fatal() {
        let mut validator = fresh_validator();
        let id = rid();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();
        validator.accept_events(&batch(id, vec![event(2, 0xa1)])).unwrap();

        // Mutating one field of the start marker must trigger the
        // session-fatal structural-conflict path and leave state
        // untouched.
        let mut different_start = started(id, "GET");
        different_start.method = "POST".to_string();
        let err = validator.accept_started(&different_start, CaptureMode::Standard).unwrap_err();
        assert!(err.is_session_fatal());
        assert!(matches!(err, IngestError::StartedConflict(rid_check) if rid_check == id));
        assert_eq!(validator.highest_contiguous_seq(id), Some(2));

        validator.accept_finished(&finished(id, 2)).unwrap();
        let mut different_finish = finished(id, 2);
        different_finish.duration_ns = 42;
        let err2 = validator.accept_finished(&different_finish).unwrap_err();
        assert!(err2.is_session_fatal());
        assert!(matches!(err2, IngestError::FinishedConflict(rid_check) if rid_check == id));
        assert_eq!(validator.lifecycle(id), Some(RecordingLifecycle::Finalizing));
    }

    #[test]
    fn new_event_after_finalizing_rejected_but_exact_duplicate_batch_accepted() {
        let mut validator = fresh_validator();
        let id = rid();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();
        validator.accept_events(&batch(id, vec![event(2, 0xa1), event(3, 0xa2)])).unwrap();
        assert_eq!(validator.accept_finished(&finished(id, 3)).unwrap(), Acceptance::Finalizing);

        // A new event past highest contiguous must be rejected.
        let err = validator.accept_events(&batch(id, vec![event(4, 0xa3)])).unwrap_err();
        assert!(matches!(
            err,
            IngestError::EventAfterFinalization {
                recording_id: rid_check,
                recording_seq: 4,
            } if rid_check == id
        ));
        assert_eq!(validator.highest_contiguous_seq(id), Some(3));

        // An all-duplicate batch is still idempotent so a lost ACK
        // can be recovered without poisoning the session.
        assert_eq!(
            validator.accept_events(&batch(id, vec![event(2, 0xa1), event(3, 0xa2)])).unwrap(),
            Acceptance::Events { accepted: 0, duplicates: 2, highest_contiguous: 3 },
        );

        // A duplicate whose payload was tampered with is still
        // session-fatal even after finalization.
        let err = validator.accept_events(&batch(id, vec![event(2, 0xff)])).unwrap_err();
        assert!(err.is_session_fatal());
        assert!(matches!(
            err,
            IngestError::ReplayPayloadMismatch {
                recording_id: rid_check,
                recording_seq: 2,
            } if rid_check == id
        ));
    }

    fn event_with_priority(seq: u64, body: u8, priority: u32) -> RecordingEvent {
        RecordingEvent { priority, ..event(seq, body) }
    }

    #[test]
    fn active_capacity_rejection_leaves_state_untouched() {
        let mut validator = tight_validator(1, 1);
        let a = rid();
        let b = rid();

        validator.accept_started(&started(a, "GET"), CaptureMode::Standard).unwrap();
        assert_eq!(
            validator.accept_events(&batch(a, vec![event(2, 0xaa)])).unwrap(),
            Acceptance::Events { accepted: 1, duplicates: 0, highest_contiguous: 2 },
        );

        // Active capacity reached; the second start is rejected
        // without disturbing the first recording.
        let err = validator.accept_started(&started(b, "GET"), CaptureMode::Standard).unwrap_err();
        assert!(matches!(err, IngestError::ActiveCapacityReached { .. }));
        assert_eq!(validator.len(), 1);
        assert_eq!(validator.highest_contiguous_seq(a), Some(2));
    }

    #[test]
    fn events_past_the_cap_are_dropped_counted_by_priority_and_never_retained() {
        // Intended contract change (owner-ordered F5): the event cap used to
        // reject the batch with EventCapacityReached; it now drops and counts.
        let mut validator = tight_validator(1, 2);
        let id = rid();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();
        // Two retained, then 4 dropped in the same batch (priorities 7, 7, 3, 0).
        let accepted = validator
            .accept_events(&batch(
                id,
                vec![
                    event_with_priority(2, 0xa0, 1),
                    event_with_priority(3, 0xa1, 1),
                    event_with_priority(4, 0xa2, 7),
                    event_with_priority(5, 0xa3, 7),
                    event_with_priority(6, 0xa4, 3),
                    event_with_priority(7, 0xa5, 0),
                ],
            ))
            .unwrap();
        assert_eq!(
            accepted,
            Acceptance::Events { accepted: 2, duplicates: 0, highest_contiguous: 7 }
        );
        let expected: std::collections::BTreeMap<u32, u64> =
            [(7, 2), (3, 1), (0, 1)].into_iter().collect();
        assert_eq!(validator.capacity_drops(id), Some(&expected));
        // Never retains more than the limit.
        assert_eq!(validator.recordings.get(&id).unwrap().event_digests.len(), 2);

        // Replays at or below the high-water mark stay duplicates, retained or
        // dropped, and a changed retained payload is still a mismatch.
        let replay = validator
            .accept_events(&batch(
                id,
                vec![
                    event_with_priority(3, 0xa1, 1),
                    event_with_priority(4, 0xa2, 7),
                    event_with_priority(7, 0xa5, 0),
                ],
            ))
            .unwrap();
        assert_eq!(
            replay,
            Acceptance::Events { accepted: 0, duplicates: 3, highest_contiguous: 7 }
        );
        assert_eq!(validator.capacity_drops(id), Some(&expected));
        let err =
            validator.accept_events(&batch(id, vec![event_with_priority(3, 0xff, 1)])).unwrap_err();
        assert!(matches!(err, IngestError::ReplayPayloadMismatch { .. }));

        // A forward gap past the cap is still a gap, and nothing is counted.
        let err =
            validator.accept_events(&batch(id, vec![event_with_priority(9, 0xa9, 3)])).unwrap_err();
        assert!(matches!(err, IngestError::RetransmissionNeeded { expected: 8, received: 9, .. }));
        assert_eq!(validator.capacity_drops(id), Some(&expected));

        // The next contiguous event keeps being dropped and counted.
        validator.accept_events(&batch(id, vec![event_with_priority(8, 0xa8, 3)])).unwrap();
        assert_eq!(validator.capacity_drops(id).unwrap().get(&3), Some(&2));

        // Finish accepts the gap at the high-water mark; a stale mark mismatches.
        let err = validator.accept_finished(&finished(id, 3)).unwrap_err();
        assert!(matches!(err, IngestError::FinishSeqMismatch { expected: 8, got: 3, .. }));
        assert_eq!(validator.accept_finished(&finished(id, 8)).unwrap(), Acceptance::Finalizing);
        let err =
            validator.accept_events(&batch(id, vec![event_with_priority(9, 0xa9, 3)])).unwrap_err();
        assert!(matches!(err, IngestError::EventAfterFinalization { .. }));
    }

    #[test]
    fn drop_accounting_is_bounded_by_distinct_priorities() {
        let mut validator = tight_validator(1, 1);
        let id = rid();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();
        validator.accept_events(&batch(id, vec![event(2, 0)])).unwrap();
        let many = (0..64_u32)
            .map(|priority| event_with_priority(3 + u64::from(priority), 1, priority))
            .collect::<Vec<_>>();
        validator.accept_events(&batch(id, many)).unwrap();
        assert_eq!(validator.capacity_drops(id).unwrap().len(), 64);
        // A 65th distinct priority is the only remaining capacity refusal and
        // is atomic.
        let err =
            validator.accept_events(&batch(id, vec![event_with_priority(67, 2, 99)])).unwrap_err();
        assert!(matches!(err, IngestError::EventCapacityReached { .. }));
        assert_eq!(validator.highest_contiguous_seq(id), Some(66));
        assert_eq!(validator.capacity_drops(id).unwrap().len(), 64);
    }

    #[test]
    fn empty_event_batch_is_successful_noop_only_for_known_recording() {
        let mut validator = fresh_validator();
        let id = rid();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();

        // Empty batch for a known recording reports the current
        // highest contiguous value without mutation.
        assert_eq!(
            validator.accept_events(&empty_batch(id)).unwrap(),
            Acceptance::Events { accepted: 0, duplicates: 0, highest_contiguous: 1 },
        );
        assert_eq!(validator.highest_contiguous_seq(id), Some(1));
        assert_eq!(validator.lifecycle(id), Some(RecordingLifecycle::Recording));
        assert_eq!(validator.len(), 1);

        // Empty batch for an unknown recording must surface
        // UnknownRecording so the adapter retransmits the
        // structural start marker before further event traffic.
        let other = rid();
        let err = validator.accept_events(&empty_batch(other)).unwrap_err();
        assert!(matches!(err, IngestError::UnknownRecording(rid_check) if rid_check == other));
        assert_eq!(validator.len(), 1);

        // Same idempotence after finalization: a known recording
        // in the Finalizing state still accepts an empty batch.
        validator.accept_events(&batch(id, vec![event(2, 0xa1)])).unwrap();
        validator.accept_finished(&finished(id, 2)).unwrap();
        assert_eq!(
            validator.accept_events(&empty_batch(id)).unwrap(),
            Acceptance::Events { accepted: 0, duplicates: 0, highest_contiguous: 2 },
        );
        assert_eq!(validator.lifecycle(id), Some(RecordingLifecycle::Finalizing));
        assert_eq!(validator.len(), 1);
    }

    #[test]
    fn exact_replay_at_u64_max_is_accepted_without_checked_arithmetic() {
        let mut validator = fresh_validator();
        let id = rid();
        let target = event(u64::MAX, 0xa1);
        let mut digests = HashMap::new();
        digests.insert(u64::MAX, event_digest(&target));

        // Inject a recording whose highest contiguous value is
        // already u64::MAX and whose only retained event digest
        // matches the event we will replay. The exact-replay path
        // must succeed without any checked_add(1) on the sequence
        // counter.
        validator._test_inject_state(id, started(id, "GET"), u64::MAX, digests);

        assert_eq!(
            validator.accept_events(&batch(id, vec![target])).unwrap(),
            Acceptance::Events { accepted: 0, duplicates: 1, highest_contiguous: u64::MAX },
        );
        assert_eq!(validator.highest_contiguous_seq(id), Some(u64::MAX));
    }

    #[test]
    fn final_contiguous_event_at_u64_max_is_accepted_without_overflow() {
        let mut validator = fresh_validator();
        let id = rid();
        let final_event = event(u64::MAX, 0xa1);

        // Inject a recording whose highest contiguous value is
        // u64::MAX - 1 with no retained digests. The single new
        // event at u64::MAX must advance the watermark to the
        // maximum without the preflight computing `seq + 1`.
        validator._test_inject_state(id, started(id, "GET"), u64::MAX - 1, HashMap::new());

        assert_eq!(
            validator.accept_events(&batch(id, vec![final_event])).unwrap(),
            Acceptance::Events { accepted: 1, duplicates: 0, highest_contiguous: u64::MAX },
        );
        assert_eq!(validator.highest_contiguous_seq(id), Some(u64::MAX));

        // A subsequent batch that replays the same event must
        // remain idempotent at the top of the sequence space.
        let replay = event(u64::MAX, 0xa1);
        assert_eq!(
            validator.accept_events(&batch(id, vec![replay])).unwrap(),
            Acceptance::Events { accepted: 0, duplicates: 1, highest_contiguous: u64::MAX },
        );
    }

    #[test]
    fn unknown_recording_id_on_event_batch_is_rejected() {
        let mut validator = fresh_validator();
        let id = rid();
        let err = validator.accept_events(&batch(id, vec![event(2, 0xaa)])).unwrap_err();
        assert!(matches!(err, IngestError::UnknownRecording(rid_check) if rid_check == id));
    }

    #[test]
    fn unknown_recording_id_on_finished_is_rejected() {
        let mut validator = fresh_validator();
        let id = rid();
        let err = validator.accept_finished(&finished(id, 1)).unwrap_err();
        assert!(matches!(err, IngestError::UnknownRecording(rid_check) if rid_check == id));
    }

    #[test]
    fn is_session_fatal_classifies_only_replay_and_structural_conflicts() {
        // Replay payload mismatch is session-fatal.
        let replay = IngestError::ReplayPayloadMismatch { recording_id: rid(), recording_seq: 3 };
        assert!(replay.is_session_fatal());

        // Structural retries/identity-order conflicts are session-fatal.
        assert!(IngestError::StartedConflict(rid()).is_session_fatal());
        assert!(IngestError::FinishedConflict(rid()).is_session_fatal());

        // Everything else is recoverable on the same recording or session.
        assert!(
            !IngestError::RetransmissionNeeded { recording_id: rid(), expected: 2, received: 4 }
                .is_session_fatal()
        );
        assert!(
            !IngestError::EventAfterFinalization { recording_id: rid(), recording_seq: 4 }
                .is_session_fatal()
        );
        assert!(!IngestError::InvalidStartSeq { recording_id: rid(), got: 7 }.is_session_fatal());
        assert!(!IngestError::InvalidRecordingId { got: 15 }.is_session_fatal());
        assert!(
            !IngestError::NonMonotonicBatch { recording_id: rid(), prev: 2, got: 1 }
                .is_session_fatal()
        );
        assert!(
            !IngestError::FinishSeqMismatch { recording_id: rid(), expected: 2, got: 3 }
                .is_session_fatal()
        );
        assert!(!IngestError::UnknownRecording(rid()).is_session_fatal());
        assert!(
            !IngestError::ActiveCapacityReached { limit: NonZeroUsize::new(1).unwrap() }
                .is_session_fatal()
        );
        assert!(
            !IngestError::EventCapacityReached {
                recording_id: rid(),
                limit: NonZeroUsize::new(1).unwrap(),
            }
            .is_session_fatal()
        );
    }

    #[test]
    fn recording_finished_map_insertion_order_is_independent_under_partial_eq() {
        // Build two finished markers whose map fields contain the
        // same key/value pairs but were inserted in opposite order.
        // `PartialEq` for the generated `RecordingFinished` walks
        // the map by content (it is a `HashMap`), so insertion
        // order must not change the structural verdict.
        let mut forward: HashMap<u32, u64> = HashMap::new();
        forward.insert(1, 10);
        forward.insert(2, 20);
        forward.insert(3, 30);
        let mut reverse: HashMap<u32, u64> = HashMap::new();
        reverse.insert(3, 30);
        reverse.insert(2, 20);
        reverse.insert(1, 10);

        let id = rid();
        let baseline = finished_with_drop_counts(id, 2, forward);
        let reordered = finished_with_drop_counts(id, 2, reverse);

        assert_eq!(baseline, reordered);

        // The validator's cloned-struct comparison must therefore
        // classify a retry that only differs in map insertion order
        // as `FinishedRetry` rather than as a session-fatal
        // conflict.
        let mut validator = fresh_validator();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();
        validator.accept_events(&batch(id, vec![event(2, 0xa1)])).unwrap();
        validator.accept_finished(&baseline).unwrap();
        assert_eq!(validator.accept_finished(&reordered).unwrap(), Acceptance::FinishedRetry);
    }

    #[test]
    fn recording_finished_changed_map_value_is_session_fatal_conflict() {
        // Build the baseline finish marker with two drop-count
        // entries, then change exactly one existing value (key 1:
        // 10 → 11) and leave the second entry untouched. The
        // identical map keys with one flipped value must flip the
        // verdict away from `FinishedRetry` and surface the
        // session-fatal `FinishedConflict`.
        let mut original_counts: HashMap<u32, u64> = HashMap::new();
        original_counts.insert(1, 10);
        original_counts.insert(2, 20);
        let mut changed_counts: HashMap<u32, u64> = HashMap::new();
        changed_counts.insert(1, 11);
        changed_counts.insert(2, 20);

        let id = rid();
        let baseline = finished_with_drop_counts(id, 2, original_counts);
        let changed = finished_with_drop_counts(id, 2, changed_counts);

        assert_ne!(baseline, changed);

        let mut validator = fresh_validator();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();
        validator.accept_events(&batch(id, vec![event(2, 0xa1)])).unwrap();
        validator.accept_finished(&baseline).unwrap();

        let err = validator.accept_finished(&changed).unwrap_err();
        assert!(err.is_session_fatal());
        assert!(matches!(err, IngestError::FinishedConflict(rid_check) if rid_check == id));
        // The recording stays sealed in Finalizing with the
        // original finish marker retained; the validator does not
        // attempt to repair a session-fatal conflict.
        assert_eq!(validator.lifecycle(id), Some(RecordingLifecycle::Finalizing));

        // The original baseline finish marker must still retry
        // successfully after the session-fatal conflict, proving
        // the validator did not mutate the stored finish and the
        // recording is still usable as evidence.
        assert_eq!(validator.accept_finished(&baseline).unwrap(), Acceptance::FinishedRetry);
    }

    #[test]
    fn changed_replay_at_u64_max_is_session_fatal_and_does_not_mutate() {
        let mut validator = fresh_validator();
        let id = rid();
        let original = event(u64::MAX, 0xa1);
        let mut digests = HashMap::new();
        digests.insert(u64::MAX, event_digest(&original));

        // Inject a recording whose highest contiguous value is
        // already u64::MAX and whose only retained event digest
        // is the original event. The tampered replay must surface
        // the session-fatal `ReplayPayloadMismatch` and leave the
        // recording untouched at the top of the sequence space.
        validator._test_inject_state(id, started(id, "GET"), u64::MAX, digests);

        let tampered = event(u64::MAX, 0xff);
        let err = validator.accept_events(&batch(id, vec![tampered])).unwrap_err();
        assert!(err.is_session_fatal());
        assert!(matches!(
            err,
            IngestError::ReplayPayloadMismatch {
                recording_id: rid_check,
                recording_seq: u64::MAX,
            } if rid_check == id
        ));
        assert_eq!(validator.highest_contiguous_seq(id), Some(u64::MAX));

        // The original exact replay must still succeed after the
        // session-fatal mismatch, proving the validator did not
        // mutate the retained digest and the recording is still
        // usable as evidence at the top of the sequence space.
        assert_eq!(
            validator.accept_events(&batch(id, vec![original])).unwrap(),
            Acceptance::Events { accepted: 0, duplicates: 1, highest_contiguous: u64::MAX },
        );
        assert_eq!(validator.highest_contiguous_seq(id), Some(u64::MAX));
    }

    #[test]
    fn config_with_limit_overrides_default_event_budget() {
        let cap = NonZeroUsize::new(3).unwrap();
        let config = IngestConfig::new(NonZeroUsize::new(2).unwrap()).with_limit(cap);
        assert_eq!(config.max_active_recordings.get(), 2);
        assert_eq!(config.event_cap_override.map(NonZeroUsize::get), Some(3));
    }

    // ---- mode-derived caps and event rules (contracts sections 3 and 4) -------------------

    fn mode_validator() -> IngestValidator {
        IngestValidator::new(IngestConfig::mode_derived(NonZeroUsize::new(8).unwrap()))
    }

    fn many_events(from: u64, to_inclusive: u64) -> Vec<RecordingEvent> {
        (from..=to_inclusive).map(|seq| event(seq, 1)).collect()
    }

    #[test]
    fn cap_standard_16384_then_partial() {
        let mut validator = mode_validator();
        let id = rid();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();
        // 16,400 events after the start marker: events 2..=16_401.
        for chunk_start in (2..=16_401_u64).step_by(1_000) {
            let end = (chunk_start + 999).min(16_401);
            validator.accept_events(&batch(id, many_events(chunk_start, end))).unwrap();
        }
        assert_eq!(validator.highest_contiguous_seq(id), Some(16_401));
        let drops = validator.capacity_drops(id).unwrap();
        assert_eq!(drops.values().sum::<u64>(), 16, "16 events past the 16,384 cap are counted");
    }

    #[test]
    fn cap_focused_131072_accepts_all() {
        let mut validator = mode_validator();
        let id = rid();
        validator.accept_started(&started(id, "GET"), CaptureMode::Focused).unwrap();
        // Exactly 131,072 events: events 2..=131_073.
        for chunk_start in (2..=131_073_u64).step_by(4_096) {
            let end = (chunk_start + 4_095).min(131_073);
            validator.accept_events(&batch(id, many_events(chunk_start, end))).unwrap();
        }
        assert_eq!(validator.highest_contiguous_seq(id), Some(131_073));
        assert!(validator.capacity_drops(id).unwrap().is_empty(), "nothing dropped at 131,072");
        validator.accept_events(&batch(id, many_events(131_074, 131_074))).unwrap();
        assert_eq!(validator.capacity_drops(id).unwrap().values().sum::<u64>(), 1);
    }

    #[test]
    fn standard_and_focused_caps_differ_for_the_same_config() {
        let config = IngestConfig::mode_derived(NonZeroUsize::new(1).unwrap());
        assert_eq!(config.event_cap(CaptureMode::Standard), 16_384);
        assert_eq!(config.event_cap(CaptureMode::Focused), 131_072);
        let legacy = IngestConfig::new(NonZeroUsize::new(1).unwrap());
        assert_eq!(legacy.event_cap(CaptureMode::Focused), DEFAULT_MAX_EVENTS_PER_RECORDING);
    }

    #[test]
    fn invalid_event_rejects_the_whole_batch_and_leaves_state_untouched() {
        let mut validator = mode_validator();
        let id = rid();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();
        let good = event(2, 1);
        let bad = RecordingEvent { kind: 77, ..event(3, 2) };
        let err = validator.accept_events(&batch(id, vec![good.clone(), bad])).unwrap_err();
        assert!(matches!(err, IngestError::UnknownEnumValue { .. }));
        assert!(!err.is_session_fatal());
        assert_eq!(validator.highest_contiguous_seq(id), Some(1), "nothing was retained");
        // The adapter resends a corrected event at the same sequence.
        validator.accept_events(&batch(id, vec![good, event(3, 2)])).unwrap();
        assert_eq!(validator.highest_contiguous_seq(id), Some(3));
    }

    #[test]
    fn line_cursor_follows_the_recordings_effective_mode() {
        use xtrace_protocol::generated::agent::{
            RecordingEventKind, SourceBinding as WireBinding, SourceRange,
        };
        let line = |seq: u64| RecordingEvent {
            kind: RecordingEventKind::LineCursor as i32,
            source: Some(SourceRange {
                path: "src/A.java".to_string(),
                start_line: 5,
                end_line: 5,
                content_hash: Bytes::from(vec![1_u8; 32]),
                ..SourceRange::default()
            }),
            source_binding: WireBinding::ObservedUnattested as i32,
            ..event(seq, 1)
        };
        let mut validator = mode_validator();
        let (standard, focused) = (rid(), rid());
        validator.accept_started(&started(standard, "GET"), CaptureMode::Standard).unwrap();
        validator.accept_started(&started(focused, "GET"), CaptureMode::Focused).unwrap();
        assert!(matches!(
            validator.accept_events(&batch(standard, vec![line(2)])).unwrap_err(),
            IngestError::LineEventNotAllowedInStandardMode { .. }
        ));
        validator.accept_events(&batch(focused, vec![line(2)])).unwrap();
    }

    #[test]
    fn per_recording_value_byte_budget_drops_and_counts_by_priority() {
        use xtrace_protocol::generated::agent::{
            CapturedValue, CapturedValueTruncated, captured_value::Value,
        };
        let big = |seq: u64| RecordingEvent {
            priority: 7,
            value: Some(CapturedValue {
                value: Some(Value::Truncated(CapturedValueTruncated {
                    preview: "x".repeat(512),
                    ..CapturedValueTruncated::default()
                })),
            }),
            ..event(seq, 1)
        };
        let id = rid();
        let mut validator = mode_validator();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();
        // Standard budget: 256 KiB of preview bytes = 512 events of 512 bytes.
        let events: Vec<_> = (2..=601).map(big).collect();
        let acceptance = validator.accept_events(&batch(id, events)).unwrap();
        assert!(matches!(acceptance, Acceptance::Events { accepted: 512, .. }));
        assert_eq!(validator.highest_contiguous_seq(id), Some(601));
        assert_eq!(validator.capacity_drops(id).unwrap().get(&7), Some(&88));
        // A dropped sequence replays as a duplicate, not a conflict.
        let replay = validator.accept_events(&batch(id, vec![big(601)])).unwrap();
        assert!(matches!(replay, Acceptance::Events { duplicates: 1, .. }));
    }

    #[test]
    fn per_recording_line_event_budget_drops_and_counts() {
        use xtrace_protocol::generated::agent::{
            RecordingEventKind, SourceBinding as WireBinding, SourceRange,
        };
        let line = |seq: u64| RecordingEvent {
            kind: RecordingEventKind::LineCursor as i32,
            priority: 3,
            source: Some(SourceRange {
                path: "src/A.java".to_string(),
                start_line: 5,
                end_line: 5,
                content_hash: Bytes::from(vec![1_u8; 32]),
                ..SourceRange::default()
            }),
            source_binding: WireBinding::ObservedUnattested as i32,
            ..event(seq, 1)
        };
        let id = rid();
        let mut validator = mode_validator();
        validator.accept_started(&started(id, "GET"), CaptureMode::Focused).unwrap();
        let events: Vec<_> = (2..=8_201).map(line).collect();
        let acceptance = validator.accept_events(&batch(id, events)).unwrap();
        assert!(matches!(acceptance, Acceptance::Events { accepted: 8_192, .. }));
        assert_eq!(validator.capacity_drops(id).unwrap().get(&3), Some(&8));
    }

    #[test]
    fn bindings_need_the_audit_flag_on_the_validator() {
        use xtrace_protocol::generated::agent::{
            BindingRole, CapturedValue, CapturedValueDropped, DropReason, NameOrigin,
            RecordingEventKind, ValueBinding, captured_value::Value,
        };
        let with_binding = RecordingEvent {
            kind: RecordingEventKind::FrameEnter as i32,
            symbol: "A.m".to_string(),
            bindings: vec![ValueBinding {
                name: "x".to_string(),
                role: BindingRole::Argument as i32,
                name_origin: NameOrigin::Declared as i32,
                value: Some(CapturedValue {
                    value: Some(Value::Dropped(CapturedValueDropped {
                        reason: DropReason::ValueBudget as i32,
                    })),
                }),
            }],
            ..event(2, 1)
        };
        let id = rid();
        let mut off = mode_validator();
        off.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();
        assert!(matches!(
            off.accept_events(&batch(id, vec![with_binding.clone()])).unwrap_err(),
            IngestError::BindingsNotAcceptedYet { .. }
        ));
        let mut on = IngestValidator::new(
            IngestConfig::mode_derived(NonZeroUsize::new(8).unwrap()).with_bindings_audit_active(),
        );
        on.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();
        on.accept_events(&batch(id, vec![with_binding])).unwrap();
    }

    #[test]
    fn started_retry_compares_the_normalized_exercise_item_id() {
        let id = rid();
        let mut validator = fresh_validator();
        let invalid =
            RecordingStarted { exercise_item_id: "not-a-uuid".to_string(), ..started(id, "GET") };
        assert_eq!(
            validator.accept_started(&invalid, CaptureMode::Standard).unwrap(),
            Acceptance::Started
        );
        // The invalid link was dropped, so the same marker without it is an exact retry.
        assert_eq!(
            validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap(),
            Acceptance::StartedRetry
        );
        let valid_id = rid();
        let uuid = "6f1c1d0e-8b8e-4c52-9a43-0f6f2d9b7a10";
        let with =
            RecordingStarted { exercise_item_id: uuid.to_string(), ..started(valid_id, "GET") };
        validator.accept_started(&with, CaptureMode::Standard).unwrap();
        assert!(
            matches!(
                validator
                    .accept_started(&started(valid_id, "GET"), CaptureMode::Standard)
                    .unwrap_err(),
                IngestError::StartedConflict(_)
            ),
            "a valid link is kept, so dropping it later is a changed start marker"
        );
    }

    #[test]
    fn finished_with_invalid_outcome_is_rejected_and_not_sealed() {
        use xtrace_protocol::generated::agent::{OutcomeKind, RecordingOutcome};
        let mut validator = fresh_validator();
        let id = rid();
        validator.accept_started(&started(id, "GET"), CaptureMode::Standard).unwrap();
        let bad = RecordingFinished {
            outcome: Some(RecordingOutcome {
                kind: OutcomeKind::Unobserved as i32,
                http_status: 200,
                ..RecordingOutcome::default()
            }),
            ..finished(id, 1)
        };
        let err = validator.accept_finished(&bad).unwrap_err();
        assert!(matches!(err, IngestError::OutcomeInvalid { .. }));
        assert!(!err.is_session_fatal());
        assert_eq!(validator.lifecycle(id), Some(RecordingLifecycle::Recording));
        let good = RecordingFinished {
            outcome: Some(RecordingOutcome {
                kind: OutcomeKind::Responded as i32,
                http_status: 204,
                ..RecordingOutcome::default()
            }),
            ..finished(id, 1)
        };
        assert_eq!(validator.accept_finished(&good).unwrap(), Acceptance::Finalizing);
    }
}
