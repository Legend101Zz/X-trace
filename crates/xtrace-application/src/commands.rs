//! Command types and their receipts.
//!
//! Commands are state-changing intentions. Every command carries an
//! idempotency key so a retry returns the same receipt. Receipts are
//! returned by value from [`Application::execute`].
//!
//! [`Application::execute`]: crate::application::Application::execute

use serde::{Deserialize, Serialize};
use xtrace_domain::{Project, ProjectId, RepositoryFingerprint, RunId};

/// Initialize a new project for a repository that has never been
/// registered with X-trace before.
#[derive(Clone, Debug)]
pub struct InitializeProject {
    /// Canonical absolute path of the repository root. The fingerprint
    /// is derived from this value; see
    /// [`xtrace_domain::RepositoryFingerprint::from_canonical_path`].
    pub canonical_repo_path: String,
    /// Display name shown in `xtrace status` and the UI surfaces.
    pub display_name: String,
    /// Caller-supplied idempotency key.
    pub idempotency_key: String,
    /// Pre-allocated stable project identifier. The CLI allocates
    /// the identifier up front because the user-data layout keys
    /// every project's directory by `ProjectId`. The application
    /// facade records the supplied identifier verbatim; omitting it
    /// is reserved for tests and future slices that have no need to
    /// pre-resolve a storage location.
    pub project_id: xtrace_domain::ProjectId,
}

/// Open an existing project. The project must already be registered.
#[derive(Clone, Debug)]
pub struct OpenProject {
    /// Canonical absolute path of the repository root.
    pub canonical_repo_path: String,
    /// Caller-supplied idempotency key.
    pub idempotency_key: String,
}

/// Commands accepted by [`Application::execute`].
///
/// [`Application::execute`]: crate::application::Application::execute
#[derive(Clone, Debug)]
pub enum Command {
    /// Create a new project.
    InitializeProject(InitializeProject),
    /// Reopen an existing project and update its `last_opened_at`.
    OpenProject(OpenProject),
}

/// Receipt returned from a successful command.
///
/// The receipt is a typed snapshot of the resulting state. Callers
/// compare the `idempotency_key` against the one they sent to detect
/// replays. The receipt implements `Serialize`/`Deserialize` so the
/// idempotency store can persist the original body verbatim and the
/// application facade can deserialize it on replay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CommandReceipt {
    /// The project was created.
    ProjectInitialized {
        /// The new project's stable identifier.
        project_id: ProjectId,
        /// The fingerprint the project was registered under.
        fingerprint: RepositoryFingerprint,
        /// Idempotency key echoed from the request.
        idempotency_key: String,
    },
    /// An existing project was opened.
    ProjectOpened {
        /// The project's stable identifier.
        project_id: ProjectId,
        /// Idempotency key echoed from the request.
        idempotency_key: String,
    },
    /// A run receipt was allocated.
    RunAllocated {
        /// The new run's stable identifier.
        run_id: RunId,
        /// Idempotency key echoed from the request.
        idempotency_key: String,
    },
}

impl CommandReceipt {
    /// Returns the receipt's idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        match self {
            Self::ProjectInitialized { idempotency_key, .. }
            | Self::ProjectOpened { idempotency_key, .. }
            | Self::RunAllocated { idempotency_key, .. } => idempotency_key,
        }
    }
}

/// Reference to a project's hydrated aggregate. Used by command
/// receipts that need to return the full project rather than just its
/// identifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectSnapshot {
    /// The hydrated project aggregate.
    pub project: Project,
}
