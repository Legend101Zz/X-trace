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

    /// Per-recording capacity-drop accounting is exhausted.
    ///
    /// Events past the retained-digest budget are no longer an error:
    /// they are dropped, counted by priority, and the recording degrades
    /// to partial. This is returned only when the drop ledger itself would
    /// need more distinct priority buckets than its fixed bound, so the
    /// validator never retains more than its limit.
    #[error("recording {recording_id} reached event digest capacity {limit}")]
    EventCapacityReached {
        /// Recording whose event budget was exhausted.
        recording_id: RecordingId,
        /// Configured maximum number of events retained.
        limit: NonZeroUsize,
    },

    /// Event {recording_seq} rejected: event carries more bindings than the capture mode allows.
    #[error("event seq {recording_seq}: event carries more bindings than the capture mode allows")]
    BindingsOverBudget {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: binding name is longer than 128 bytes.
    #[error("event seq {recording_seq}: binding name is longer than 128 bytes")]
    BindingNameTooLong {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: binding name is empty or contains a control character.
    #[error("event seq {recording_seq}: binding name is empty or contains a control character")]
    BindingNameInvalid {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: value preview is longer than the capture mode allows.
    #[error("event seq {recording_seq}: value preview is longer than the capture mode allows")]
    BindingPreviewTooLong {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: preview and name bytes on one event exceed the capture mode budget.
    #[error(
        "event seq {recording_seq}: preview and name bytes on one event exceed the capture mode budget"
    )]
    EventValueBytesOverBudget {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: value binding or captured value carries no value.
    #[error("event seq {recording_seq}: value binding or captured value carries no value")]
    ValueMissing {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: line cursor needs a source range on a single line greater than zero with a source-claiming binding.
    #[error(
        "event seq {recording_seq}: line cursor needs a source range on a single line greater than zero with a source-claiming binding"
    )]
    LineCursorInvalid {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: line cursor in a standard-mode recording.
    #[error("event seq {recording_seq}: line cursor in a standard-mode recording")]
    LineEventNotAllowedInStandardMode {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: local variable binding in a standard-mode recording.
    #[error("event seq {recording_seq}: local variable binding in a standard-mode recording")]
    LocalsNotAllowedInStandardMode {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: gap event payload is missing, misplaced or inconsistent.
    #[error("event seq {recording_seq}: gap event payload is missing, misplaced or inconsistent")]
    GapPayloadInvalid {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: redacted value carries a content hash.
    #[error("event seq {recording_seq}: redacted value carries a content hash")]
    HashOnRedacted {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: source range and source binding disagree.
    #[error("event seq {recording_seq}: source range and source binding disagree")]
    SourceBindingMismatch {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: source path, lines or content hash are invalid.
    #[error("event seq {recording_seq}: source path, lines or content hash are invalid")]
    SourcePathInvalid {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: binding role is not legal on this event kind.
    #[error("event seq {recording_seq}: binding role is not legal on this event kind")]
    BindingRoleKindMismatch {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: value bindings are not accepted until the daemon audit redactor is active.
    #[error(
        "event seq {recording_seq}: value bindings are not accepted until the daemon audit redactor is active"
    )]
    BindingsNotAcceptedYet {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: redaction rule id does not match the allowed pattern.
    #[error("event seq {recording_seq}: redaction rule id does not match the allowed pattern")]
    RedactionRuleIdInvalid {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: interaction field is outside its allowed vocabulary or bounds.
    #[error(
        "event seq {recording_seq}: interaction field is outside its allowed vocabulary or bounds"
    )]
    InteractionFieldInvalid {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: captured value content hash is missing or does not match the emitted preview.
    #[error(
        "event seq {recording_seq}: captured value content hash is missing or does not match the emitted preview"
    )]
    ContentHashInvalid {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: frame event carries no symbol, or any event carries a
    /// symbol over its byte bound.
    #[error("event seq {recording_seq}: event symbol is missing or over its bound")]
    SymbolRequired {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: exception payload field exceeds its bound.
    #[error("event seq {recording_seq}: exception payload field exceeds its bound")]
    ExceptionFieldInvalid {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// Event {recording_seq} rejected: runtime facts field exceeds its bound.
    #[error("event seq {recording_seq}: runtime facts field exceeds its bound")]
    RuntimeFactsInvalid {
        /// Sequence of the offending event.
        recording_seq: u64,
    },

    /// A wire enum carried an unknown or unspecified number where a specified value is required.
    ///
    /// Unknown values are rejected, never coerced.
    #[error("event seq {recording_seq}: unknown or unspecified enum value in {field}")]
    UnknownEnumValue {
        /// Sequence of the offending event.
        recording_seq: u64,
        /// Wire field that carried the bad value.
        field: &'static str,
    },

    /// `RecordingFinished.outcome` violates the outcome rules.
    #[error("recording {recording_id}: finished outcome invalid ({reason})")]
    OutcomeInvalid {
        /// Recording whose finish marker was rejected.
        recording_id: RecordingId,
        /// Stable reason string from the first violated rule.
        reason: &'static str,
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
