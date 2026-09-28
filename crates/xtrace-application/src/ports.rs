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
//! Slice 1A ships two ports: [`ProjectRepository`] for the project
//! aggregate and [`IdempotencyStore`] for the durable command-receipt
//! table. Future slices add `RunRepository`, `RecordingRepository`,
//! `CatalogRepository`, `SessionRepository`, and the inbound ports
//! used by the language adapters and the daemon HTTP surface.

use xtrace_domain::{
    CorrelationId, Project, ProjectId, RepositoryFingerprint, Run, RunId, RunKind, RunState,
    WallTime,
};

use crate::error::PortError;

/// Persistence contract for project aggregates.
///
/// Implementations are expected to enforce uniqueness on
/// `canonical_repo_hash`, propagate integrity errors as
/// [`crate::error::PortErrorKind::Corruption`], and translate
/// schema-compatibility rejections into
/// [`crate::error::PortErrorKind::Compatibility`].
pub trait ProjectRepository: Send + Sync {
    /// Inserts a new project. Returns
    /// [`crate::error::PortErrorKind::AlreadyExists`] when another
    /// project already owns the same fingerprint.
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

/// One durable command receipt persisted by [`IdempotencyStore`].
///
/// The receipt stores the serialized receipt body, the canonical
/// input digest computed by the application layer, the correlation
/// ID assigned to the original request, and the wall-clock time the
/// receipt was written. Subsequent calls with the same idempotency
/// key use these fields to detect replays and conflicts.
#[derive(Clone, Debug)]
pub struct StoredReceipt {
    /// Stable identifier of the project the command targeted.
    pub project_id: ProjectId,
    /// Kind of command the receipt belongs to (e.g. `initialize_project`).
    pub command_kind: String,
    /// Caller-supplied idempotency key.
    pub idempotency_key: String,
    /// Canonical-input digest the application layer computed.
    pub input_digest: String,
    /// Original correlation ID assigned to the producing request.
    pub correlation_id: CorrelationId,
    /// Wall-clock time the receipt was first recorded.
    pub created_at: WallTime,
    /// JSON-serialized receipt body returned to the original caller.
    pub receipt_json: String,
}

/// Durability contract for command idempotency.
///
/// Every command that can be replayed must record its receipt through
/// this port before the application returns success. The application
/// facade consults [`IdempotencyStore::lookup_receipt`] before
/// executing a command and returns either the original receipt
/// (same canonical input) or an `XTR-COMMAND-409` error
/// (different canonical input). A `None` result means the key has
/// never been used.
pub trait IdempotencyStore: Send + Sync {
    /// Looks up a stored receipt for the supplied command kind and
    /// idempotency key. Returns `Ok(None)` when the key has never
    /// been recorded.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] with kind `Corruption`, `Transport`, or
    /// `Internal` for storage failures. Validation failures are
    /// surfaced as `Validation`.
    fn lookup_receipt(
        &self,
        command_kind: &str,
        idempotency_key: &str,
    ) -> Result<Option<StoredReceipt>, PortError>;

    /// Persists a receipt. Implementations must treat
    /// `(command_kind, idempotency_key)` as unique within a project
    /// and surface an `AlreadyExists`
    /// [`crate::error::PortErrorKind`] when the key is reused with
    /// a different canonical input. A retry with the same canonical
    /// input must be a no-op so callers can record idempotently.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] with kind `AlreadyExists` when a
    /// different input is already stored, `Validation` for invalid
    /// arguments, and `Corruption`, `Transport`, or `Internal` for
    /// storage failures.
    fn record_receipt(&self, receipt: &StoredReceipt) -> Result<(), PortError>;
}
