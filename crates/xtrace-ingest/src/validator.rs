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

use std::collections::HashMap;
use std::num::NonZeroUsize;

use blake3::Hasher;
use prost::Message as _;
use uuid::Uuid;
use xtrace_domain::RecordingId;
use xtrace_protocol::generated::agent::{
    EventBatch, RecordingEvent, RecordingFinished, RecordingStarted,
};

use crate::error::IngestError;

/// Approved per-recording event budget.
///
/// Matches the default documented in `03-program-design.md` §6 and is
/// the explicit fallback inside [`IngestConfig::new`]. Tests that need
/// to exercise the boundary use [`IngestConfig::with_limit`] to lower
/// the budget without redefining the production default.
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
/// `03-program-design.md` §6. `max_events_per_recording` is set to
/// the approved 2,048-event default by [`IngestConfig::new`]; tests
/// override it through [`IngestConfig::with_limit`].
#[derive(Clone, Debug)]
pub struct IngestConfig {
    /// Maximum number of recordings the validator will track
    /// concurrently (`Recording` plus `Finalizing`).
    pub max_active_recordings: NonZeroUsize,
    /// Maximum number of `RecordingEvent` entries retained per
    /// recording. The structural start marker is not counted.
    pub max_events_per_recording: NonZeroUsize,
}

impl IngestConfig {
    /// Builds a configuration with the approved default event budget.
    ///
    /// `max_active_recordings` is supplied by the caller because the
    /// active budget depends on the surrounding daemon topology; the
    /// per-recording event budget is fixed at the approved default
    /// and falls back to [`NonZeroUsize::MIN`] only if a future edit
    /// changes [`DEFAULT_MAX_EVENTS_PER_RECORDING`] to `0`, so this
    /// constructor never panics.
    #[must_use]
    pub fn new(max_active_recordings: NonZeroUsize) -> Self {
        let max_events_per_recording =
            NonZeroUsize::new(DEFAULT_MAX_EVENTS_PER_RECORDING).unwrap_or(NonZeroUsize::MIN);
        Self { max_active_recordings, max_events_per_recording }
    }

    /// Overrides the per-recording event budget. Intended for tests
    /// that need to exercise the [`IngestError::EventCapacityReached`]
    /// boundary without sending the production 2,048-event budget.
    #[must_use]
    pub const fn with_limit(mut self, max_events: NonZeroUsize) -> Self {
        self.max_events_per_recording = max_events;
        self
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
}

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
    ) -> Result<Acceptance, IngestError> {
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
                started: started.clone(),
                finished: None,
                highest_contiguous: 1,
                event_digests: HashMap::new(),
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
    /// [`IngestError::EventCapacityReached`].
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
        let max_events = self.config.max_events_per_recording.get();

        let mut new_count: usize = 0;
        let mut duplicates: usize = 0;
        let mut candidate_highest: u64 = state.highest_contiguous;
        let mut pending: Vec<(u64, [u8; 32])> = Vec::with_capacity(batch.events.len());

        for event in &batch.events {
            let seq = event.recording_seq;
            let digest = event_digest(event);

            if seq <= candidate_highest {
                match state.event_digests.get(&seq) {
                    Some(stored) if *stored == digest => {
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
                // Capacity check happens before mutation so a full
                // batch is rejected atomically rather than
                // partially retained.
                if event_digest_count.saturating_add(new_count).saturating_add(1) > max_events {
                    return Err(IngestError::EventCapacityReached {
                        recording_id: id,
                        limit: self.config.max_events_per_recording,
                    });
                }
                pending.push((seq, digest));
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
        state.highest_contiguous = candidate_highest;

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
            RecordingState { started, finished: None, highest_contiguous, event_digests },
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
        Acceptance, IngestConfig, IngestError, IngestValidator, RecordingLifecycle, event_digest,
    };

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

        assert_eq!(validator.accept_started(&started(a, "GET")).unwrap(), Acceptance::Started);
        assert_eq!(validator.lifecycle(a), Some(RecordingLifecycle::Recording));
        assert_eq!(validator.highest_contiguous_seq(a), Some(1));
        assert_eq!(validator.len(), 1);

        assert_eq!(validator.accept_started(&started(b, "POST")).unwrap(), Acceptance::Started);
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
        let err = validator.accept_started(&payload).unwrap_err();
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
        let err = validator.accept_started(&payload).unwrap_err();
        assert!(matches!(err, IngestError::InvalidRecordingId { got: 17 }));
        assert_eq!(validator.len(), 0);
    }

    #[test]
    fn wrong_start_recording_seq_is_rejected() {
        let mut validator = fresh_validator();
        let id = rid();
        let mut payload = started(id, "GET");
        payload.recording_seq = 7;
        let err = validator.accept_started(&payload).unwrap_err();
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
        validator.accept_started(&started(id, "GET")).unwrap();

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
        validator.accept_started(&started(id, "GET")).unwrap();

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
        validator.accept_started(&started(id, "GET")).unwrap();

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
        validator.accept_started(&started(id, "GET")).unwrap();

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
        validator.accept_started(&started(id, "GET")).unwrap();

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
        validator.accept_started(&started(id, "GET")).unwrap();
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

        assert_eq!(validator.accept_started(&started(id, "GET")).unwrap(), Acceptance::Started);
        assert_eq!(
            validator.accept_started(&started(id, "GET")).unwrap(),
            Acceptance::StartedRetry,
        );
        assert_eq!(
            validator.accept_started(&started(id, "GET")).unwrap(),
            Acceptance::StartedRetry,
        );

        validator.accept_events(&batch(id, vec![event(2, 0xa1), event(3, 0xa2)])).unwrap();

        assert_eq!(validator.accept_finished(&finished(id, 3)).unwrap(), Acceptance::Finalizing,);
        assert_eq!(validator.accept_finished(&finished(id, 3)).unwrap(), Acceptance::FinishedRetry,);
        // After finalization the started retry is still idempotent,
        // never a duplicate-conflict return.
        assert_eq!(
            validator.accept_started(&started(id, "GET")).unwrap(),
            Acceptance::StartedRetry,
        );
    }

    #[test]
    fn changed_started_or_finished_retries_are_session_fatal() {
        let mut validator = fresh_validator();
        let id = rid();
        validator.accept_started(&started(id, "GET")).unwrap();
        validator.accept_events(&batch(id, vec![event(2, 0xa1)])).unwrap();

        // Mutating one field of the start marker must trigger the
        // session-fatal structural-conflict path and leave state
        // untouched.
        let mut different_start = started(id, "GET");
        different_start.method = "POST".to_string();
        let err = validator.accept_started(&different_start).unwrap_err();
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
        validator.accept_started(&started(id, "GET")).unwrap();
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

    #[test]
    fn active_and_event_capacity_rejections_leave_state_untouched() {
        let mut validator = tight_validator(1, 1);
        let a = rid();
        let b = rid();

        validator.accept_started(&started(a, "GET")).unwrap();
        assert_eq!(
            validator.accept_events(&batch(a, vec![event(2, 0xaa)])).unwrap(),
            Acceptance::Events { accepted: 1, duplicates: 0, highest_contiguous: 2 },
        );

        // Active capacity reached; the second start is rejected
        // without disturbing the first recording.
        let err = validator.accept_started(&started(b, "GET")).unwrap_err();
        assert!(matches!(err, IngestError::ActiveCapacityReached { .. }));
        assert_eq!(validator.len(), 1);
        assert_eq!(validator.highest_contiguous_seq(a), Some(2));

        // Event capacity reached; the new contiguous event is
        // rejected without disturbing the digest table.
        let err = validator.accept_events(&batch(a, vec![event(3, 0xab)])).unwrap_err();
        assert!(matches!(err, IngestError::EventCapacityReached { .. }));
        assert_eq!(validator.highest_contiguous_seq(a), Some(2));

        // A mixed batch whose suffix would overflow capacity is
        // rejected atomically without partial retention.
        let err =
            validator.accept_events(&batch(a, vec![event(2, 0xaa), event(3, 0xab)])).unwrap_err();
        assert!(matches!(err, IngestError::EventCapacityReached { .. }));
        assert_eq!(validator.highest_contiguous_seq(a), Some(2));
    }

    #[test]
    fn empty_event_batch_is_successful_noop_only_for_known_recording() {
        let mut validator = fresh_validator();
        let id = rid();
        validator.accept_started(&started(id, "GET")).unwrap();

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
        validator.accept_started(&started(id, "GET")).unwrap();
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
        validator.accept_started(&started(id, "GET")).unwrap();
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
        assert_eq!(config.max_events_per_recording.get(), 3);
    }
}
