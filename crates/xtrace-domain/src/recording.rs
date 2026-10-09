//! Recording aggregate.
//!
//! A recording is one observed request execution. It is immutable after
//! finalization; recovery may move it from `Recording` to `Partial` or
//! `Invalid`, but it never rewrites accepted event objects.
//!
//! See `03-program-design.md` §5.3 for the recording state machine and
//! `03a-domain-and-storage.md` §3 for the frame model.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ids::{
    FrameId, InteractionId, OperationId, ProjectId, RecordingId, RuntimeSessionId,
    SourceArtifactId, SourceRevisionId,
};
use crate::provenance::EvidenceRef;
use crate::time::{MonotonicNs, WallTime};
use crate::value::CapturedValue;

/// Lifecycle state of a recording.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingState {
    /// `RecordingStarted` accepted, events still arriving.
    Recording,
    /// Final markers received, sealing in progress.
    Finalizing,
    /// Recording is durable and complete.
    Complete,
    /// Recording finalized with declared gaps.
    Partial,
    /// Recording could not be trusted (sequence / correlation violation).
    Invalid,
}

impl RecordingState {
    /// Returns `true` if the recording is in a terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Partial | Self::Invalid)
    }

    /// Returns the wire string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Finalizing => "finalizing",
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Invalid => "invalid",
        }
    }
}

/// Frame kind. Replay navigation and view rendering branch on this.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameKind {
    /// Top-level request entry.
    Request,
    /// Framework boundary (Spring, Express, Servlet, ...).
    Framework,
    /// Application method entry or exit.
    Method,
    /// Source line cursor within an active method.
    Line,
    /// Database, outbound HTTP, or other interaction.
    Interaction,
    /// Caught or propagated exception.
    Exception,
    /// Response produced by the application.
    Response,
    /// Declared gap with a stable reason.
    Gap,
}

impl FrameKind {
    /// Returns the wire string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Framework => "framework",
            Self::Method => "method",
            Self::Line => "line",
            Self::Interaction => "interaction",
            Self::Exception => "exception",
            Self::Response => "response",
            Self::Gap => "gap",
        }
    }
}

/// Replay position assigned by the recording assembler after
/// validation.
///
/// `ordinal` is monotonic within a recording; `depth` reflects the call
/// stack; `branch` distinguishes alternative paths within the same
/// depth; `elapsed_ns` is relative to the recording start.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReplayPosition {
    /// Ordinal within the recording. Strictly increasing.
    pub ordinal: u64,
    /// Depth in the call stack.
    pub depth: u32,
    /// Branch index used when alternative paths coexist.
    pub branch: u32,
    /// Monotonic nanoseconds since the recording start.
    pub elapsed_ns: MonotonicNs,
}

/// Source range pointing at a frame's code location.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameSource {
    /// Source artifact containing the location.
    pub source_artifact_id: SourceArtifactId,
    /// Inclusive start line (`1`-based).
    pub start_line: u32,
    /// Optional inclusive end line. `None` for a single-line frame.
    pub end_line: Option<u32>,
}

/// Replayable frame within a recording.
///
/// Frames are immutable. Linear replay reads them in `ReplayPosition`
/// order; Canvas replay projects them onto a graph.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Frame {
    /// Stable identifier.
    pub id: FrameId,
    /// Owning recording.
    pub recording_id: RecordingId,
    /// Position assigned by the assembler.
    pub position: ReplayPosition,
    /// Parent frame in the call stack, if any.
    pub parent: Option<FrameId>,
    /// Async parent frame, if any.
    pub async_parent: Option<FrameId>,
    /// Frame kind.
    pub kind: FrameKind,
    /// Optional symbol reference (e.g. `OrderController.create`).
    pub symbol: Option<String>,
    /// Optional source range.
    pub source: Option<FrameSource>,
    /// Captured values at the frame's observation point.
    pub values: Vec<ValueBinding>,
    /// Optional result value (method return, exception payload, ...).
    pub result: Option<CapturedValue>,
    /// Evidence reference describing how the frame was produced.
    pub evidence: EvidenceRef,
}

/// Named captured value bound to a frame.
///
/// `name` is the local variable, parameter, or field name. The value
/// itself is always a [`CapturedValue`] so redaction state is preserved.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ValueBinding {
    /// Stable binding name (`request`, `this`, parameter name, ...).
    pub name: String,
    /// Captured value with explicit capture state.
    pub value: CapturedValue,
}

/// Interaction captured within a recording.
///
/// Database calls, outbound HTTP, messaging, and other boundaries are
/// modelled uniformly so the UI can render them in a single timeline.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Interaction {
    /// Stable identifier.
    pub id: InteractionId,
    /// Owning recording.
    pub recording_id: RecordingId,
    /// Frame that owns the interaction boundary.
    pub frame_id: FrameId,
    /// Position within the recording.
    pub position: ReplayPosition,
    /// Kind of boundary.
    pub kind: InteractionKind,
    /// Stable labels for the target (driver, table, host, ...).
    pub target: InteractionTarget,
    /// Optional captured request payload summary.
    pub request_summary: Option<CapturedValue>,
    /// Optional captured response payload summary.
    pub response_summary: Option<CapturedValue>,
    /// Optional captured error summary.
    pub error: Option<CapturedValue>,
    /// Wall-clock time the interaction opened.
    pub opened_at: WallTime,
    /// Wall-clock time the interaction closed.
    pub closed_at: Option<WallTime>,
    /// Evidence reference describing how the interaction was produced.
    pub evidence: EvidenceRef,
}

/// Kind of captured interaction.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionKind {
    /// JDBC or other database call.
    Database,
    /// Outbound HTTP or HTTPS call.
    OutboundHttp,
    /// Messaging boundary.
    Messaging,
    /// Filesystem boundary.
    Filesystem,
    /// Other framework boundary.
    Framework,
}

impl InteractionKind {
    /// Returns the wire string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::OutboundHttp => "outbound_http",
            Self::Messaging => "messaging",
            Self::Filesystem => "filesystem",
            Self::Framework => "framework",
        }
    }
}

/// Stable target labels for an interaction.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InteractionTarget {
    /// Driver or client identifier (e.g. `org.postgresql.Driver`).
    pub driver: Option<String>,
    /// Database schema or catalog.
    pub schema: Option<String>,
    /// Table or collection.
    pub table: Option<String>,
    /// Outbound host (HTTP or messaging).
    pub host: Option<String>,
    /// HTTP method or messaging verb.
    pub method: Option<String>,
    /// Outbound path or queue name.
    pub path: Option<String>,
    /// Free-form labels keyed by a stable name (`query_kind`,
    /// `client_name`, ...).
    pub labels: BTreeMap<String, String>,
}

/// Recording aggregate root.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Recording {
    /// Stable identifier.
    pub id: RecordingId,
    /// Owning project.
    pub project_id: ProjectId,
    /// Owning runtime session.
    pub runtime_session_id: RuntimeSessionId,
    /// Resolved operation, if any. Unknown operations are stored with
    /// `None` and reconciled later; the recording is never discarded
    /// because the catalog is incomplete.
    pub operation_id: Option<OperationId>,
    /// Source revision active when the recording was captured.
    pub source_revision_id: Option<SourceRevisionId>,
    /// Lifecycle state.
    pub state: RecordingState,
    /// Wall-clock time the recording opened.
    pub opened_at: WallTime,
    /// Wall-clock time the recording completed. `None` while open.
    pub completed_at: Option<WallTime>,
    /// Adapter-reported duration in nanoseconds.
    pub duration_ns: Option<MonotonicNs>,
    /// Optional request summary (sanitized method, URL shape, ...).
    pub request_summary: Option<CapturedValue>,
    /// Optional response summary (status, sanitized headers).
    pub response_summary: Option<CapturedValue>,
    /// Number of frames persisted for the recording.
    pub frame_count: u32,
    /// Number of interactions persisted for the recording.
    pub interaction_count: u32,
    /// Number of gap frames persisted for the recording.
    pub gap_count: u32,
    /// Reason the recording reached its current state, when terminal.
    pub completion_reason: Option<String>,
    /// Evidence reference for the recording as a whole.
    pub evidence: EvidenceRef,
}

impl Recording {
    /// Returns `true` if the recording has reached a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_state_terminal_predicate() {
        assert!(!RecordingState::Recording.is_terminal());
        assert!(!RecordingState::Finalizing.is_terminal());
        assert!(RecordingState::Complete.is_terminal());
        assert!(RecordingState::Partial.is_terminal());
        assert!(RecordingState::Invalid.is_terminal());
    }

    #[test]
    fn frame_kinds_round_trip_through_strings() {
        for kind in [
            FrameKind::Request,
            FrameKind::Framework,
            FrameKind::Method,
            FrameKind::Line,
            FrameKind::Interaction,
            FrameKind::Exception,
            FrameKind::Response,
            FrameKind::Gap,
        ] {
            // Wire form must round-trip through serde.
            let json = serde_json::to_string(&kind).expect("serializes");
            let parsed: FrameKind = serde_json::from_str(&json).expect("frame kind round-trips");
            assert_eq!(parsed, kind);
            assert_eq!(kind.as_str(), json.trim_matches('"'));
        }
    }
}

/// Role a value plays at the event it is bound to (ADR 0003 section 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingRole {
    /// A method argument; legal on `FRAME_ENTER`.
    Argument,
    /// A method return value; legal on `FRAME_EXIT`.
    Return,
    /// A local variable; legal on `LINE_CURSOR` in focused recordings.
    Local,
    /// The in-flight exception; legal on `FRAME_THROW` and `EXCEPTION`.
    Exception,
    /// The receiver (`this`); legal on `FRAME_ENTER`.
    Receiver,
}

impl BindingRole {
    /// Returns the snake_case string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Argument => "argument",
            Self::Return => "return",
            Self::Local => "local",
            Self::Exception => "exception",
            Self::Receiver => "receiver",
        }
    }
}

/// Where a binding's name came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameOrigin {
    /// Taken from debug metadata (declared in source).
    Declared,
    /// Synthesized by the adapter (for example `arg0`).
    Synthesized,
}

impl NameOrigin {
    /// Returns the snake_case string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Synthesized => "synthesized",
        }
    }
}

/// A named value observed at an event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValueBinding {
    /// Binding name, 1 to 128 UTF-8 bytes.
    pub name: String,
    /// Role the value plays at the event.
    pub role: BindingRole,
    /// Whether the name is declared or synthesized.
    pub name_origin: NameOrigin,
    /// The value, never absent: an unobserved value is `Unavailable` or `Dropped`.
    pub value: CapturedValue,
}

/// Why events were not recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    /// The per-recording line budget was exhausted.
    LineBudget,
    /// The per-recording value budget was exhausted.
    ValueBudget,
    /// The daemon throttled the adapter.
    Throttle,
    /// The adapter queue was full.
    QueueFull,
    /// Correlation between events was lost.
    CorrelationLost,
    /// The class could not be transformed for probing.
    ClassNotTransformed,
    /// The module loaded before probes were armed.
    ModuleLoadedBeforeArm,
    /// A generated file was observed with no source map.
    SourceMapAbsent,
    /// A handled exception cannot be observed.
    HandledExceptionUnobserved,
    /// A child process is not instrumented.
    ChildProcessNotInstrumented,
    /// The bootstrap material was already consumed.
    BootstrapConsumed,
}

impl GapReason {
    /// Returns the snake_case string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LineBudget => "line_budget",
            Self::ValueBudget => "value_budget",
            Self::Throttle => "throttle",
            Self::QueueFull => "queue_full",
            Self::CorrelationLost => "correlation_lost",
            Self::ClassNotTransformed => "class_not_transformed",
            Self::ModuleLoadedBeforeArm => "module_loaded_before_arm",
            Self::SourceMapAbsent => "source_map_absent",
            Self::HandledExceptionUnobserved => "handled_exception_unobserved",
            Self::ChildProcessNotInstrumented => "child_process_not_instrumented",
            Self::BootstrapConsumed => "bootstrap_consumed",
        }
    }
}

/// A coalesced description of events that were not recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gap {
    /// Why the events were not recorded.
    pub reason: GapReason,
    /// How many events the gap stands for; at least 1.
    pub count: u64,
    /// First recording sequence the gap covers; 0 when unknown.
    pub first_seq: u64,
    /// Last recording sequence the gap covers; 0 when unknown.
    pub last_seq: u64,
}

/// How a request ended, as the adapter observed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    /// A response was produced.
    Responded,
    /// An exception propagated out of the application.
    ExceptionPropagated,
    /// The client went away before a response.
    ClientAborted,
    /// The adapter did not observe the outcome.
    Unobserved,
}

impl OutcomeKind {
    /// Returns the snake_case string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Responded => "responded",
            Self::ExceptionPropagated => "exception_propagated",
            Self::ClientAborted => "client_aborted",
            Self::Unobserved => "unobserved",
        }
    }
}

/// Sanitized exception carried by an outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeException {
    /// Exception type name, at most 256 bytes.
    pub exception_type: String,
    /// Sanitized message, at most 512 bytes.
    pub message: String,
}

/// The observed end of a request. It never overrides completion (honesty rule R7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingOutcome {
    /// How the request ended.
    pub kind: OutcomeKind,
    /// HTTP status; `None` when not observed.
    pub http_status: Option<u16>,
    /// Present exactly when `kind` is `ExceptionPropagated`.
    pub exception: Option<OutcomeException>,
    /// Frame that last observed the throw.
    pub thrown_from_event_id: Option<String>,
}

impl RecordingOutcome {
    /// The outcome synthesized for terminal evidence that predates outcome capture (v4..v6 rows).
    #[must_use]
    pub const fn legacy_unobserved() -> Self {
        Self {
            kind: OutcomeKind::Unobserved,
            http_status: None,
            exception: None,
            thrown_from_event_id: None,
        }
    }

    /// Checks the structural rules shared by ingest and terminal-evidence verification: status in
    /// 100..=599, an exception present iff the kind is `ExceptionPropagated`, and `Unobserved`
    /// carrying no status.
    ///
    /// # Errors
    ///
    /// Returns a stable reason string naming the first violated rule.
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Some(status) = self.http_status {
            if !(100..=599).contains(&status) {
                return Err("http_status_out_of_range");
            }
        }
        if self.exception.is_some() != (self.kind == OutcomeKind::ExceptionPropagated) {
            return Err("exception_presence_mismatch");
        }
        if self.kind == OutcomeKind::Unobserved && self.http_status.is_some() {
            return Err("unobserved_with_status");
        }
        if let Some(ex) = &self.exception {
            if ex.exception_type.len() > 256 {
                return Err("exception_type_too_long");
            }
            if ex.message.len() > 512 {
                return Err("exception_message_too_long");
            }
        }
        if self.thrown_from_event_id.as_deref().is_some_and(|id| id.len() > 128) {
            return Err("thrown_from_event_id_too_long");
        }
        Ok(())
    }
}

#[cfg(test)]
mod binding_outcome_tests {
    use super::*;

    fn outcome(kind: OutcomeKind) -> RecordingOutcome {
        RecordingOutcome { kind, http_status: None, exception: None, thrown_from_event_id: None }
    }

    #[test]
    fn outcome_exception_requires_payload() {
        assert_eq!(
            outcome(OutcomeKind::ExceptionPropagated).validate(),
            Err("exception_presence_mismatch")
        );
        let mut with = outcome(OutcomeKind::ExceptionPropagated);
        with.exception =
            Some(OutcomeException { exception_type: "E".to_string(), message: "m".to_string() });
        assert_eq!(with.validate(), Ok(()));
        let mut stray = outcome(OutcomeKind::Responded);
        stray.exception = with.exception;
        assert_eq!(stray.validate(), Err("exception_presence_mismatch"));
    }

    #[test]
    fn outcome_unobserved_with_status_rejected() {
        let mut o = outcome(OutcomeKind::Unobserved);
        o.http_status = Some(200);
        assert_eq!(o.validate(), Err("unobserved_with_status"));
        assert_eq!(outcome(OutcomeKind::Unobserved).validate(), Ok(()));
    }

    #[test]
    fn outcome_status_range_and_responded_without_status() {
        let mut o = outcome(OutcomeKind::Responded);
        assert_eq!(o.validate(), Ok(()), "responded with an unobserved status is legal");
        o.http_status = Some(99);
        assert_eq!(o.validate(), Err("http_status_out_of_range"));
        o.http_status = Some(600);
        assert_eq!(o.validate(), Err("http_status_out_of_range"));
        o.http_status = Some(599);
        assert_eq!(o.validate(), Ok(()));
    }

    #[test]
    fn outcome_text_bounds_are_byte_bounds() {
        let mut o = outcome(OutcomeKind::ExceptionPropagated);
        o.exception =
            Some(OutcomeException { exception_type: "E".to_string(), message: "x".repeat(513) });
        assert_eq!(o.validate(), Err("exception_message_too_long"));
        o.exception =
            Some(OutcomeException { exception_type: "E".repeat(257), message: String::new() });
        assert_eq!(o.validate(), Err("exception_type_too_long"));
    }

    #[test]
    fn legacy_outcome_is_unobserved_not_responded() {
        let legacy = RecordingOutcome::legacy_unobserved();
        assert_eq!(legacy.kind, OutcomeKind::Unobserved);
        assert_eq!(legacy.http_status, None);
        assert_eq!(legacy.validate(), Ok(()));
    }

    #[test]
    fn enum_strings_match_serde() {
        for role in [
            BindingRole::Argument,
            BindingRole::Return,
            BindingRole::Local,
            BindingRole::Exception,
            BindingRole::Receiver,
        ] {
            assert_eq!(serde_json::to_string(&role).unwrap(), format!("\"{}\"", role.as_str()));
        }
        for reason in [GapReason::LineBudget, GapReason::ChildProcessNotInstrumented] {
            assert_eq!(serde_json::to_string(&reason).unwrap(), format!("\"{}\"", reason.as_str()));
        }
        assert_eq!(
            serde_json::to_string(&OutcomeKind::ClientAborted).unwrap(),
            "\"client_aborted\""
        );
        assert_eq!(serde_json::to_string(&NameOrigin::Synthesized).unwrap(), "\"synthesized\"");
    }
}
