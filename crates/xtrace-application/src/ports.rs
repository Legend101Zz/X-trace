//! Outbound ports.
//!
//! Ports are the abstractions that the application layer depends on;
//! infrastructure (the SQLite store in `xtrace-store`, the future
//! runtime adapters, and the daemon HTTP layer) supplies the
//! implementations. Every port keeps its surface small, returns a
//! [`PortError`] for failures, and is fully synchronous so a future
//! slice can move them onto an async runtime without changing the
//! trait signatures.
//!
//! Slice 1A ships a single port: [`ProjectRepository`]. Future slices
//! add `RunRepository`, `RecordingRepository`, `CatalogRepository`,
//! `SessionRepository`, and the inbound ports used by the language
//! adapters and the daemon HTTP surface.

use xtrace_domain::{
    Project, ProjectId, RepositoryFingerprint, Run, RunId, RunKind, RunState, WallTime,
};

use crate::error::PortError;

/// Persistence contract for project aggregates.
///
/// Implementations are expected to enforce uniqueness on
/// `canonical_repo_hash`, propagate integrity errors as
/// [`PortErrorKind::Corruption`], and translate schema-compatibility
/// rejections into [`PortErrorKind::Compatibility`].
pub trait ProjectRepository: Send + Sync {
    /// Inserts a new project. Returns [`PortErrorKind::AlreadyExists`]
    /// when another project already owns the same fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] with kind `Validation` for invalid input,
    /// `AlreadyExists` when the fingerprint is already registered, and
    /// `Corruption`, `Transport`, or `Internal` for storage failures.
    fn insert_project(&self, project: &Project) -> Result<(), PortError>;

    /// Loads a project by its canonical repository fingerprint.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] with kind `NotFound` when no project has
    /// been registered for the supplied fingerprint.
    fn load_project_by_fingerprint(
        &self,
        fingerprint: &RepositoryFingerprint,
    ) -> Result<Project, PortError>;

    /// Lists every project registered with the local store.
    ///
    /// Implementations return projects in deterministic order
    /// (ascending `created_at`, ties broken by `project_id`) so the
    /// CLI output is stable across runs.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] with kind `Corruption`, `Transport`, or
    /// `Internal` for storage failures.
    fn list_projects(&self) -> Result<Vec<Project>, PortError>;

    /// Loads a project by its stable identifier.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] with kind `NotFound` when no project with
    /// the supplied identifier exists.
    fn load_project_by_id(&self, project_id: ProjectId) -> Result<Project, PortError>;

    /// Updates the `last_opened_at` column for a project. Implementations
    /// must treat the operation as idempotent: the write must not fail
    /// when the timestamp is unchanged from the previous value.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] with kind `NotFound` when the project is
    /// missing.
    fn touch_last_opened(
        &self,
        project_id: ProjectId,
        opened_at: WallTime,
    ) -> Result<(), PortError>;

    /// Inserts a run receipt.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] with kind `AlreadyExists` when an existing
    /// run already owns the same `(project_id, idempotency_key)` pair,
    /// `NotFound` when `project_id` does not resolve to a known
    /// project, and `Validation` for invalid input.
    fn insert_run(
        &self,
        run: &Run,
        project_id: ProjectId,
        idempotency_key: &str,
    ) -> Result<(), PortError>;

    /// Loads a run receipt by its stable identifier.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] with kind `NotFound` when the run is
    /// missing.
    fn load_run(&self, run_id: RunId) -> Result<Run, PortError>;

    /// Updates the lifecycle state of an existing run.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] with kind `NotFound` when the run is
    /// missing and `Conflict` when the supplied state is incompatible
    /// with the current state.
    fn update_run_state(
        &self,
        run_id: RunId,
        new_state: RunState,
        finished_at: Option<WallTime>,
        error_code: Option<&str>,
    ) -> Result<(), PortError>;

    /// Allocates a fresh run identifier paired with the supplied
    /// [`RunKind`]. Implementations persist the row in the `Requested`
    /// state so external work begins against an existing receipt.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] with kind `NotFound` when the project is
    /// missing and `Internal` when identifier allocation fails.
    fn allocate_run(
        &self,
        project_id: ProjectId,
        kind: RunKind,
        requested_by: &str,
        idempotency_key: &str,
        requested_at: WallTime,
    ) -> Result<RunId, PortError>;
}
