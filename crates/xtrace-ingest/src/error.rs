//! Typed errors returned by the recording assembler boundary.
//!
//! Every variant names the structural or sequencing problem it reports so
//! callers can branch on a stable, typed reason instead of pattern
//! matching on a string. No variant carries an `XTR-*` code: the
//! domain error vocabulary is owned by `xtrace-domain`, and this
//! boundary stops short of that translation because the downstream
//! durability layer decides how each reason is presented to a client.
//!
//! [`IngestError::is_session_fatal`] distinguishes the reasons that
//! poison a runtime session from those that allow the adapter to retry
//! the same payload, drop optional detail, or surface a transcript gap
//! for retransmission. Only replay-payload mismatch and a changed
//! structural retry/identity-order conflict are session-fatal today;
//! every other variant is recoverable on the same recording or session.
//!
//! Sequence exhaustion is intentionally not modelled as an error
//! variant. The event preflight uses `u64::MAX` inclusive bounds so
//! both exact replays at the maximum and a final contiguous event at
//! the maximum are accepted without checked arithmetic overflow.

use std::num::NonZeroUsize;

use xtrace_domain::RecordingId;

/// Outcome of a single wire payload rejection at the recording boundary.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// `RecordingStarted` carried a `recording_seq` other than `1`.
    ///
    /// The protocol reserves `recording_seq == 1` for the structural
    /// start marker; any other value is rejected before mutating
    /// validator state.
    #[error("recording_started for {recording_id} carried recording_seq {got}; expected 1")]
    InvalidStartSeq {
        /// Recording the malformed start belongs to.
        recording_id: RecordingId,
        /// Sequence value reported by the adapter.
        got: u64,
    },

    /// The recording ID has no accepted `RecordingStarted` yet.
    ///
    /// Returns [`IngestError::UnknownRecording`] for the first event or
    /// finish that arrives ahead of its start, so the adapter can
    /// retransmit the structural marker without losing ordering
    /// guarantees.
    #[error("unknown recording id {0}")]
    UnknownRecording(RecordingId),

    /// `recording_seq` values inside a single `EventBatch` were not
    /// strictly ascending.
    ///
    /// Strict monotonicity inside a batch is required so a duplicated
    /// or reordered transport does not silently change the recorded
    /// ordering. The batch is rejected before any event is retained.
    #[error("event batch for {recording_id} is not strictly ascending at seq {got} after {prev}")]
    NonMonotonicBatch {
        /// Recording the malformed batch belongs to.
        recording_id: RecordingId,
        /// Previously seen sequence in the batch.
        prev: u64,
        /// Offending sequence reported by the adapter.
        got: u64,
    },

    /// `recording_id` bytes are not exactly 16 bytes long.
    ///
    /// The wire format carries `recording_id` as an opaque byte string,
    /// but every domain `RecordingId` is a 16-byte UUID. Any other
    /// length is rejected before the recording is touched.
    #[error("recording_id has {got} bytes; expected exactly 16")]
    InvalidRecordingId {
        /// Number of bytes the adapter supplied.
        got: usize,
    },

    /// Replay payload mismatch detected.
    ///
    /// The adapter retransmitted a `recording_seq` that was already
    /// accepted, but the deterministic event payload digest differs
    /// from the digest stored at first acceptance. This is treated as
    /// a session-fatal identity conflict; the validator leaves state
    /// untouched so the downstream supervisor can quarantine the
    /// session without losing previously accepted evidence.
    #[error(
        "recording {recording_id} event seq {recording_seq} payload digest differs from previously accepted value"
    )]
    ReplayPayloadMismatch {
        /// Recording the mismatched event belongs to.
        recording_id: RecordingId,
        /// Sequence number whose digest differs.
        recording_seq: u64,
    },

    /// Forward gap in event sequence.
    ///
    /// The first event in the batch has a `recording_seq` that is
    /// strictly greater than the validator's next contiguous value.
    /// The adapter is asked to retransmit the missing range; state is
    /// left unchanged.
    #[error("recording {recording_id} expected next event seq {expected}, received {received}")]
    RetransmissionNeeded {
        /// Recording the gap belongs to.
        recording_id: RecordingId,
        /// Next contiguous `recording_seq` the validator requires.
        expected: u64,
        /// First `recording_seq` the batch actually carries.
        received: u64,
    },

    /// New event after finalization.
    ///
    /// The recording has already transitioned to
    /// [`crate::RecordingLifecycle::Finalizing`]; any
    /// `recording_seq` greater than the highest contiguous value is
    /// rejected because the recording is sealed. An all-duplicate
    /// batch is still accepted as an idempotent retry so a lost ACK
    /// can be recovered.
    #[error(
        "recording {recording_id} already finalizing; event seq {recording_seq} is past highest "
    )]
    EventAfterFinalization {
        /// Recording the late event belongs to.
        recording_id: RecordingId,
        /// Sequence number the adapter sent.
        recording_seq: u64,
    },

    /// `RecordingFinished.final_recording_seq` does not match the
    /// highest contiguous `recording_seq`.
    ///
    /// The finish marker must reference the exact final sequence the
    /// validator has accepted; any other value is rejected as a
    /// structural conflict.
    #[error(
        "recording {recording_id} finished with final_recording_seq {got}; expected {expected}"
    )]
    FinishSeqMismatch {
        /// Recording the mismatched finish belongs to.
        recording_id: RecordingId,
        /// Highest contiguous `recording_seq` the validator holds.
        expected: u64,
        /// Value the adapter reported in `final_recording_seq`.
        got: u64,
    },

    /// `RecordingStarted` for an already known recording ID has
    /// changed.
    ///
    /// The validator retains a cloned `RecordingStarted` from the
    /// first accepted start marker. A second start whose fields
    /// differ under `PartialEq` (which the generated prost types
    /// derive field-by-field) is a typed session-fatal identity
    /// conflict; the recording is left in its existing state so a
    /// downstream supervisor can quarantine the session without
    /// losing evidence.
    #[error("recording {0} received a changed RecordingStarted; structural conflict")]
    StartedConflict(RecordingId),

    /// `RecordingFinished` for an already finalized recording ID has
    /// changed.
    ///
    /// The validator retains a cloned `RecordingFinished` from the
    /// first accepted finish marker. A second finish whose fields
    /// differ under `PartialEq` is a typed session-fatal identity
    /// conflict; the recording stays sealed in its existing state.
    #[error("recording {0} received a changed RecordingFinished; structural conflict")]
    FinishedConflict(RecordingId),

    /// Active recording capacity reached.
    ///
    /// The validator cannot accept another `RecordingStarted` without
    /// violating the configured active-recording budget. The
    /// [`crate::IngestValidator`] leaves state untouched and returns
    /// this typed reason so the downstream daemon can decide whether
    /// to apply priority-based degradation or `DropNotice` handling.
    /// This crate does not perform that policy itself.
    #[error("active recording capacity {limit} reached")]
    ActiveCapacityReached {
        /// Configured maximum number of concurrent recordings.
        limit: NonZeroUsize,
    },

    /// Per-recording event digest capacity reached.
    ///
    /// The validator cannot retain another event without violating
    /// the configured event budget. Retained event digests are not
    /// reclaimed during the validator lifetime in this slice.
    #[error("recording {recording_id} reached event digest capacity {limit}")]
    EventCapacityReached {
        /// Recording whose event budget was exhausted.
        recording_id: RecordingId,
        /// Configured maximum number of events retained.
        limit: NonZeroUsize,
    },
}

impl IngestError {
    /// Returns `true` only for the reasons that poison a runtime
    /// session and force the downstream supervisor to quarantine the
    /// adapter connection.
    ///
    /// Session-fatal reasons are limited to:
    ///
    /// - [`IngestError::ReplayPayloadMismatch`] — same sequence,
    ///   different payload, so the transport cannot be trusted to
    ///   carry identical bytes twice.
    /// - [`IngestError::StartedConflict`] — a second
    ///   `RecordingStarted` for a known recording ID has a different
    ///   `PartialEq` view, so identity or ordering is corrupt.
    /// - [`IngestError::FinishedConflict`] — a second
    ///   `RecordingFinished` for a finalized recording ID has a
    ///   different `PartialEq` view.
    ///
    /// Every other variant is recoverable on the same recording or
    /// session: capacity exhaustion, retransmission hints, late events
    /// after finalization, monotonicity violations, malformed IDs, and
    /// unknown recording IDs do not by themselves force a session
    /// quarantine.
    #[must_use]
    pub const fn is_session_fatal(&self) -> bool {
        matches!(
            self,
            Self::ReplayPayloadMismatch { .. }
                | Self::StartedConflict(_)
                | Self::FinishedConflict(_)
        )
    }
}
