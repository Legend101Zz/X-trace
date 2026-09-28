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
