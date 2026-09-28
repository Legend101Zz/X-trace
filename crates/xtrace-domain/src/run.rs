//! Run aggregate.
//!
//! A run is one explicit user request for work: a scan, a launch, an
//! attach, an exercise, an export, or a migration. Runs are durable
//! before external work begins so retries can return the original
//! receipt.
//!
//! See `03-program-design.md` §5.1 for the run state machine.

use serde::{Deserialize, Serialize};

use crate::ids::{ProjectId, RunId};
use crate::time::WallTime;

/// Kind of work a run represents. Each kind has a single terminal state
/// and produces a deterministic receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunKind {
    /// Create a new catalog revision.
    Scan,
    /// Launch a process through X-trace and capture requests.
    LaunchCapture,
    /// Attach to a compatible running process.
    AttachCapture,
    /// Arm focused capture for the next matching request.
    FocusedCapture,
    /// Exercise endpoints against a reviewed plan.
    Exercise,
    /// Project one or more export formats.
    Export,
    /// Apply a retention preview.
    Retention,
    /// Apply a schema migration.
    Migration,
}

impl RunKind {
    /// Returns the wire string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::LaunchCapture => "launch_capture",
            Self::AttachCapture => "attach_capture",
            Self::FocusedCapture => "focused_capture",
            Self::Exercise => "exercise",
            Self::Export => "export",
            Self::Retention => "retention",
            Self::Migration => "migration",
        }
    }
}

/// Run lifecycle state.
///
/// The full state machine is documented in `03-program-design.md` §5.1.
/// Slice 1A persists the subset that the CLI surfaces through
/// `xtrace status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    /// Created durably but no external work has started.
    Requested,
    /// Resolving inputs (repository, adapter, target process, ...).
    Preparing,
    /// External work has begun.
    Running,
    /// Work finished and produced a durable result.
    Succeeded,
    /// Work finished and produced a partial result with declared gaps.
    Partial,
    /// Work failed.
    Failed,
    /// Work was cancelled by an explicit user action.
    Cancelled,
}

impl RunState {
    /// Returns `true` if the state is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Partial | Self::Failed | Self::Cancelled)
    }

    /// Returns the wire string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Preparing => "preparing",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Run aggregate root.
///
/// A run is uniquely identified by `(project_id, idempotency_key)`.
/// Retrying with the same key returns the original receipt; reusing a
/// key with different input fails with `XTR-COMMAND-409`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    /// Stable identifier.
    pub id: RunId,
    /// Owning project.
    pub project_id: ProjectId,
    /// Kind of work.
    pub kind: RunKind,
    /// Lifecycle state.
    pub state: RunState,
    /// Wall-clock time the run was requested.
    pub requested_at: WallTime,
    /// Wall-clock time external work started. `None` while still
    /// `Requested` or `Preparing`.
    pub started_at: Option<WallTime>,
    /// Wall-clock time the run reached a terminal state. `None` until
    /// the run terminates.
    pub finished_at: Option<WallTime>,
    /// Stable identifier of the user who requested the run. Stored
    /// for audit; never crosses the client API.
    pub requested_by: String,
    /// Idempotency key supplied by the caller.
    pub idempotency_key: String,
    /// Stable error code if the run failed. `None` otherwise.
    pub error_code: Option<String>,
}

impl Run {
    /// Returns `true` if the run has reached a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}
