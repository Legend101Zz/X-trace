//! Application facade.
//!
//! The [`Application`] type is the single entry point for clients
//! (CLI, TUI, daemon HTTP handlers). It owns the [`RequestContext`]
//! factory, validates incoming commands and queries, orchestrates the
//! relevant ports, and translates internal failures into typed
//! [`xtrace_domain::AppError`] values.
//!
//! The facade is intentionally generic over a single repository port
//! and an idempotency-store port in Slice 1A. Future slices
//! parameterize over additional ports without breaking the public
//! signature.

use std::sync::Arc;

use xtrace_domain::{
    AppError, CorrelationId, ErrorCategory, ErrorCode, Project, ProjectId, RepositoryFingerprint,
    RetryAdvice, RunKind, WallTime, codes,
};

use crate::commands::{Command, CommandReceipt, InitializeProject, OpenProject};
use crate::error::{PortError, PortErrorKind};
use crate::ports::{IdempotencyStore, ProjectRepository, StoredReceipt};
use crate::queries::{
    CapabilityReport, GetProject, ProjectStatus, Query, QueryResult, StoreStatusReport,
};

/// Per-request context propagated to every command and query.
///
/// The context is intentionally tiny: it carries the caller's
/// identity for audit, the correlation ID for diagnostics, and a
/// wall-clock instant. Authentication and authorization are added
/// in a later slice.
#[derive(Clone, Debug)]
pub struct RequestContext {
    /// Stable identifier of the human or automation that issued the
    /// command. Never embedded in error messages.
    pub requested_by: String,
    /// Wall-clock instant the request was accepted by the facade.
    pub requested_at: WallTime,
    /// Correlation ID surfaced to clients for diagnostics.
    pub correlation_id: CorrelationId,
}

impl RequestContext {
    /// Constructs a new request context.
    #[must_use]
    pub fn new(requested_by: impl Into<String>, requested_at: WallTime) -> Self {
        Self {
            requested_by: requested_by.into(),
            requested_at,
            correlation_id: CorrelationId::new(),
        }
    }
}

/// Application facade. Cheap to clone; the repository is reference
/// counted so the same handle can be shared across threads.
#[derive(Clone)]
pub struct Application<R: ProjectRepository, I: IdempotencyStore> {
    repository: Arc<R>,
    idempotency: Arc<I>,
    /// Schema version this binary initializes a fresh store with.
    target_schema_version: u32,
    /// XTP-Agent protocol major version this binary speaks.
    protocol_major: u32,
    /// XTP-Agent protocol minor version this binary speaks.
    protocol_minor: u32,
}

impl<R: ProjectRepository, I: IdempotencyStore> Application<R, I> {
    /// Constructs a new application facade over the supplied port
    /// implementations.
    #[must_use]
    pub fn new(
        repository: R,
        idempotency: I,
        target_schema_version: u32,
        protocol_major: u32,
        protocol_minor: u32,
    ) -> Self {
        Self {
            repository: Arc::new(repository),
            idempotency: Arc::new(idempotency),
            target_schema_version,
            protocol_major,
            protocol_minor,
        }
    }

    /// Executes a single command and returns its receipt.
    ///
    /// # Errors
    ///
    /// Returns [`xtrace_domain::AppError`] for every validation or
    /// port failure. Validation failures are surfaced as
    /// [`ErrorCategory::Validation`]; port failures are translated
    /// into the matching [`ErrorCategory`] before crossing the
    /// boundary. A reused idempotency key with a different canonical
    /// input surfaces as `XTR-COMMAND-409`.
    pub fn execute(
        &self,
        command: Command,
        ctx: &RequestContext,
    ) -> Result<CommandReceipt, AppError> {
        match command {
            Command::InitializeProject(cmd) => self.initialize_project(cmd, ctx),
            Command::OpenProject(cmd) => self.open_project(cmd, ctx),
        }
    }

    /// Executes a single query and returns its result.
    ///
    /// # Errors
    ///
    /// Returns [`xtrace_domain::AppError`] for validation or port
    /// failures.
    pub fn query(&self, query: Query, ctx: &RequestContext) -> Result<QueryResult, AppError> {
        match query {
            Query::GetProject(query) => self.get_project(query, ctx),
            Query::GetStoreStatus(_) => self.get_store_status(ctx),
        }
    }

    /// Convenience helper that allocates a [`xtrace_domain::RunId`]
    /// through the port without exposing the port directly.
    ///
    /// # Errors
    ///
    /// Returns [`xtrace_domain::AppError`] when the project is missing or the port
    /// fails to allocate the identifier.
    pub fn allocate_run(
        &self,
        project_id: ProjectId,
        kind: RunKind,
        idempotency_key: &str,
        ctx: &RequestContext,
    ) -> Result<CommandReceipt, AppError> {
        validate_idempotency_key(idempotency_key, ctx.correlation_id)?;
        let run_id = self
            .repository
            .allocate_run(project_id, kind, &ctx.requested_by, idempotency_key, ctx.requested_at)
            .map_err(|err| port_error_to_app_error(err, ctx.correlation_id))?;
        Ok(CommandReceipt::RunAllocated { run_id, idempotency_key: idempotency_key.to_string() })
    }

    fn initialize_project(
        &self,
        cmd: InitializeProject,
        ctx: &RequestContext,
    ) -> Result<CommandReceipt, AppError> {
        validate_canonical_repo_path(&cmd.canonical_repo_path, ctx.correlation_id)?;
        validate_display_name(&cmd.display_name, ctx.correlation_id)?;
        validate_idempotency_key(&cmd.idempotency_key, ctx.correlation_id)?;
        let fingerprint = RepositoryFingerprint::from_canonical_path(&cmd.canonical_repo_path);
        let input_digest =
            canonical_input_digest(COMMAND_KIND_INIT, &cmd.canonical_repo_path, &cmd.display_name);
        let project = Project {
            id: cmd.project_id,
            canonical_repo_hash: fingerprint.clone(),
            display_name: cmd.display_name,
            created_at: ctx.requested_at,
            last_opened_at: ctx.requested_at,
            config_schema_version: 1,
            effective_config_hash: String::new(),
            active_capture_policy_id: None,
            active_redaction_policy_id: None,
        };
        let requested_receipt = CommandReceipt::ProjectInitialized {
            project_id: project.id,
            fingerprint,
            idempotency_key: cmd.idempotency_key.clone(),
        };
        let receipt_json = serde_json::to_string(&requested_receipt).map_err(|err| {
            AppError::new(
                ErrorCode::new("XTR-INTERNAL-SERIALIZE"),
                ErrorCategory::Internal,
                "failed to serialize command receipt",
                RetryAdvice::None,
                ctx.correlation_id,
            )
            .with_detail("reason", err.to_string())
        })?;
        let requested = StoredReceipt {
            project_id: project.id,
            command_kind: COMMAND_KIND_INIT.to_string(),
            idempotency_key: cmd.idempotency_key,
            input_digest,
            correlation_id: ctx.correlation_id,
            created_at: ctx.requested_at,
            receipt_json,
        };
        let stored = self
            .repository
            .initialize_project_with_receipt(&project, &requested)
            .map_err(|err| port_error_to_app_error(err, ctx.correlation_id))?;
        if stored.project_id != requested.project_id
            || stored.command_kind != requested.command_kind
            || stored.idempotency_key != requested.idempotency_key
            || stored.input_digest != requested.input_digest
        {
            return Err(AppError::new(
                ErrorCode::new("XTR-PROJECT-RECOVERY-REQUIRED"),
                ErrorCategory::Corruption,
                "stored initialization receipt does not match this project",
                RetryAdvice::None,
                ctx.correlation_id,
            ));
        }
        let returned = deserialize_initialize_receipt(&stored, ctx.correlation_id)?;
        match &returned {
            CommandReceipt::ProjectInitialized {
                project_id,
                fingerprint: actual,
                idempotency_key,
            } if *project_id == project.id
                && *actual == project.canonical_repo_hash
                && idempotency_key == &stored.idempotency_key =>
            {
                Ok(returned)
            }
            _ => Err(AppError::new(
                ErrorCode::new("XTR-PROJECT-RECOVERY-REQUIRED"),
                ErrorCategory::Corruption,
                "stored initialization receipt body is inconsistent",
                RetryAdvice::None,
                ctx.correlation_id,
            )),
        }
    }

    fn open_project(
        &self,
        cmd: OpenProject,
        ctx: &RequestContext,
    ) -> Result<CommandReceipt, AppError> {
        let input_digest = canonical_input_digest(COMMAND_KIND_OPEN, &cmd.canonical_repo_path, "");
        if let Some(replay) =
            self.replay_receipt(COMMAND_KIND_OPEN, &cmd.idempotency_key, ctx.correlation_id)?
        {
            if replay.input_digest == input_digest {
                return deserialize_open_receipt(&replay, ctx.correlation_id);
            }
            return Err(idempotency_conflict(
                &cmd.idempotency_key,
                replay.correlation_id,
                ctx.correlation_id,
            ));
        }
        validate_canonical_repo_path(&cmd.canonical_repo_path, ctx.correlation_id)?;
        validate_idempotency_key(&cmd.idempotency_key, ctx.correlation_id)?;
        let fingerprint = RepositoryFingerprint::from_canonical_path(&cmd.canonical_repo_path);
        let project = match self.repository.load_project_by_fingerprint(&fingerprint) {
            Ok(project) => project,
            Err(err) => return Err(port_error_to_app_error(err, ctx.correlation_id)),
        };
        self.repository
            .touch_last_opened(project.id(), ctx.requested_at)
            .map_err(|err| port_error_to_app_error(err, ctx.correlation_id))?;
        let receipt = CommandReceipt::ProjectOpened {
            project_id: project.id(),
            idempotency_key: cmd.idempotency_key.clone(),
        };
        self.persist_receipt(
            project.id(),
            COMMAND_KIND_OPEN,
            &cmd.idempotency_key,
            &input_digest,
            &receipt,
            ctx,
        )?;
        Ok(receipt)
    }

    fn get_project(
        &self,
        query: GetProject,
        ctx: &RequestContext,
    ) -> Result<QueryResult, AppError> {
        validate_canonical_repo_path(&query.canonical_repo_path, ctx.correlation_id)?;
        let fingerprint = RepositoryFingerprint::from_canonical_path(&query.canonical_repo_path);
        match self.repository.load_project_by_fingerprint(&fingerprint) {
            Ok(project) => Ok(QueryResult::Project(crate::commands::ProjectSnapshot::new(project))),
            Err(err) => Err(port_error_to_app_error(err, ctx.correlation_id)),
        }
    }

    fn get_store_status(&self, ctx: &RequestContext) -> Result<QueryResult, AppError> {
        // Status reports must never claim capture or replay support in
        // Slice 1A. The capability summary is the truthful spine view.
        let capabilities = CapabilityReport {
            store_schema_version: self.target_schema_version,
            protocol_major: self.protocol_major,
            protocol_minor: self.protocol_minor,
            capture_supported: false,
            replay_supported: false,
        };
        let projects = match self.repository.list_projects() {
            Ok(projects) => projects,
            Err(err) => return Err(port_error_to_app_error(err, ctx.correlation_id)),
        };
        let projects = projects
            .into_iter()
            .map(|project| ProjectStatus {
                project_id: project.id(),
                fingerprint: project.canonical_repo_hash.clone(),
                display_name: project.display_name.clone(),
                created_at: project.created_at.to_rfc3339(),
                last_opened_at: project.last_opened_at.to_rfc3339(),
            })
            .collect();
        let report = StoreStatusReport {
            capabilities,
            current_schema_version: self.target_schema_version,
            target_schema_version: self.target_schema_version,
            projects,
            diagnostics: Default::default(),
        };
        let _ = ctx;
        Ok(QueryResult::StoreStatus(report))
    }

    fn replay_receipt(
        &self,
        command_kind: &str,
        idempotency_key: &str,
        correlation_id: CorrelationId,
    ) -> Result<Option<StoredReceipt>, AppError> {
        // The idempotency port mints its own infrastructure
        // correlation ID per call. We pass it through to
        // `port_error_to_app_error` so the original infrastructure
        // identity is preserved as a diagnostic detail while the
        // request correlation ID surfaces on the boundary.
        match self.idempotency.lookup_receipt(command_kind, idempotency_key) {
            Ok(receipt) => Ok(receipt),
            Err(err) => Err(port_error_to_app_error(err, correlation_id)),
        }
    }

    fn persist_receipt(
        &self,
        project_id: ProjectId,
        command_kind: &str,
        idempotency_key: &str,
        input_digest: &str,
        receipt: &CommandReceipt,
        ctx: &RequestContext,
    ) -> Result<(), AppError> {
        let receipt_json = serde_json::to_string(receipt).map_err(|err| {
            AppError::new(
                ErrorCode::new("XTR-INTERNAL-SERIALIZE"),
                ErrorCategory::Internal,
                "failed to serialize command receipt",
                RetryAdvice::None,
                ctx.correlation_id,
            )
            .with_detail("reason", err.to_string())
        })?;
        let stored = StoredReceipt {
            project_id,
            command_kind: command_kind.to_string(),
            idempotency_key: idempotency_key.to_string(),
            input_digest: input_digest.to_string(),
            correlation_id: ctx.correlation_id,
            created_at: ctx.requested_at,
            receipt_json,
        };
        // A duplicate `(command_kind, idempotency_key)` pair with a
        // different `input_digest` means a concurrent caller raced
        // through validation with the same key. The persistence
        // layer reports `AlreadyExists`; we surface it as a real
        // `XTR-COMMAND-409` because the canonical inputs genuinely
        // differ.
        match self.idempotency.record_receipt(&stored) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == PortErrorKind::AlreadyExists => {
                Err(idempotency_conflict(idempotency_key, ctx.correlation_id, ctx.correlation_id))
            }
            Err(err) => Err(port_error_to_app_error(err, ctx.correlation_id)),
        }
    }
}

/// Stable command kind tags used by the idempotency store.
const COMMAND_KIND_INIT: &str = "initialize_project";
const COMMAND_KIND_OPEN: &str = "open_project";

/// Computes a canonical input digest for a command.
///
/// The digest is a single BLAKE3-256 hash over a deterministic,
/// newline-separated encoding of the command arguments, rendered in
/// the canonical `b3:<lowercase hex>` form via
/// [`xtrace_domain::ContentHash::from_blake3_digest`]. The encoding
/// is intentionally stringly-typed so the hash changes only when
/// the canonical input changes; whitespace, JSON formatting, or
/// other transient encodings must not affect the digest.
fn canonical_input_digest(
    command_kind: &str,
    canonical_repo_path: &str,
    display_name: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(command_kind.as_bytes());
    hasher.update(b"\n");
    hasher.update(canonical_repo_path.as_bytes());
    hasher.update(b"\n");
    hasher.update(display_name.as_bytes());
    xtrace_domain::ContentHash::from_blake3_digest(hasher.finalize()).to_canonical()
}

fn deserialize_initialize_receipt(
    stored: &StoredReceipt,
    correlation_id: CorrelationId,
) -> Result<CommandReceipt, AppError> {
    serde_json::from_str(&stored.receipt_json).map_err(|err| {
        AppError::new(
            ErrorCode::new("XTR-INTERNAL-DESERIALIZE"),
            ErrorCategory::Internal,
            "failed to deserialize a stored receipt",
            RetryAdvice::None,
            correlation_id,
        )
        .with_detail("reason", err.to_string())
    })
}

fn deserialize_open_receipt(
    stored: &StoredReceipt,
    correlation_id: CorrelationId,
) -> Result<CommandReceipt, AppError> {
    serde_json::from_str(&stored.receipt_json).map_err(|err| {
        AppError::new(
            ErrorCode::new("XTR-INTERNAL-DESERIALIZE"),
            ErrorCategory::Internal,
            "failed to deserialize a stored receipt",
            RetryAdvice::None,
            correlation_id,
        )
        .with_detail("reason", err.to_string())
    })
}

fn idempotency_conflict(
    idempotency_key: &str,
    original_correlation_id: CorrelationId,
    current_correlation_id: CorrelationId,
) -> AppError {
    AppError::new(
        codes::COMMAND_IDEMPOTENCY_CONFLICT.clone(),
        ErrorCategory::Conflict,
        "idempotency key reused with a different canonical input",
        RetryAdvice::None,
        current_correlation_id,
    )
    .with_detail("idempotency_key", idempotency_key.to_string())
    .with_detail("original_correlation_id", original_correlation_id.to_string())
}

/// Validates that a canonical repository path is a non-empty UTF-8
/// string with no NUL bytes. The store performs no path normalization
/// here so callers see the exact value they sent in error reports.
fn validate_canonical_repo_path(
    value: &str,
    correlation_id: CorrelationId,
) -> Result<(), AppError> {
    if value.is_empty() {
        return Err(validation_error(
            "XTR-VALIDATION-PATH",
            "canonical repository path must not be empty",
            correlation_id,
        ));
    }
    if value.contains('\0') {
        return Err(validation_error(
            "XTR-VALIDATION-PATH",
            "canonical repository path must not contain NUL bytes",
            correlation_id,
        ));
    }
    Ok(())
}

/// Validates a display name.
fn validate_display_name(value: &str, correlation_id: CorrelationId) -> Result<(), AppError> {
    if value.trim().is_empty() {
        return Err(validation_error(
            "XTR-VALIDATION-DISPLAY-NAME",
            "display name must not be empty",
            correlation_id,
        ));
    }
    if value.len() > 128 {
        return Err(validation_error(
            "XTR-VALIDATION-DISPLAY-NAME",
            "display name must be at most 128 characters",
            correlation_id,
        ));
    }
    Ok(())
}

/// Validates an idempotency key.
fn validate_idempotency_key(value: &str, correlation_id: CorrelationId) -> Result<(), AppError> {
    if value.is_empty() {
        return Err(validation_error(
            "XTR-VALIDATION-IDEMPOTENCY",
            "idempotency key must not be empty",
            correlation_id,
        ));
    }
    if value.len() > 128 {
        return Err(validation_error(
            "XTR-VALIDATION-IDEMPOTENCY",
            "idempotency key must be at most 128 characters",
            correlation_id,
        ));
    }
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        return Err(validation_error(
            "XTR-VALIDATION-IDEMPOTENCY",
            "idempotency key must not contain control characters",
            correlation_id,
        ));
    }
    Ok(())
}

fn validation_error(
    code: &'static str,
    message: &'static str,
    correlation_id: CorrelationId,
) -> AppError {
    AppError::new(
        ErrorCode::new(code),
        ErrorCategory::Validation,
        message,
        RetryAdvice::None,
        correlation_id,
    )
}

/// Translates an internal [`PortError`] into the public
/// [`xtrace_domain::AppError`] contract. The request correlation ID
/// is preserved on the surface; the infrastructure-generated
/// correlation ID is retained as a diagnostic detail so a future
/// slice can correlate the two without
/// losing the request identity. The mapping is total so port authors
/// cannot accidentally leak a variant through the boundary.
pub(crate) fn port_error_to_app_error(
    err: PortError,
    request_correlation_id: CorrelationId,
) -> AppError {
    let infra_correlation_id = err.correlation_id();
    let mut builder = AppError::new(
        port_code(err.kind()),
        port_category(err.kind()),
        err.message(),
        port_retry(err.kind()),
        request_correlation_id,
    );
    if let Some(source) = err.source() {
        if !source.is_empty() {
            builder = builder.with_detail("source", source.to_string());
        }
    }
    if infra_correlation_id != request_correlation_id {
        builder =
            builder.with_detail("infrastructure_correlation_id", infra_correlation_id.to_string());
    }
    builder
}

fn port_category(kind: PortErrorKind) -> ErrorCategory {
    match kind {
        PortErrorKind::Validation => ErrorCategory::Validation,
        PortErrorKind::AlreadyExists => ErrorCategory::Conflict,
        PortErrorKind::NotFound => ErrorCategory::NotFound,
        PortErrorKind::Conflict => ErrorCategory::Conflict,
        PortErrorKind::Compatibility => ErrorCategory::Compatibility,
        PortErrorKind::Resource => ErrorCategory::Resource,
        PortErrorKind::Corruption => ErrorCategory::Corruption,
        PortErrorKind::Transport => ErrorCategory::Transport,
        PortErrorKind::Internal => ErrorCategory::Internal,
    }
}

fn port_retry(kind: PortErrorKind) -> RetryAdvice {
    match kind {
        PortErrorKind::Validation
        | PortErrorKind::AlreadyExists
        | PortErrorKind::NotFound
        | PortErrorKind::Conflict
        | PortErrorKind::Compatibility
        | PortErrorKind::Corruption => RetryAdvice::None,
        PortErrorKind::Resource | PortErrorKind::Transport | PortErrorKind::Internal => {
            RetryAdvice::Immediate
        }
    }
}

fn port_code(kind: PortErrorKind) -> ErrorCode {
    let raw = match kind {
        PortErrorKind::Validation => "XTR-PORT-VALIDATION",
        PortErrorKind::AlreadyExists => "XTR-PORT-ALREADY-EXISTS",
        PortErrorKind::NotFound => "XTR-PORT-NOT-FOUND",
        PortErrorKind::Conflict => "XTR-PORT-CONFLICT",
        PortErrorKind::Compatibility => "XTR-PORT-COMPATIBILITY",
        PortErrorKind::Resource => "XTR-PORT-RESOURCE",
        PortErrorKind::Corruption => "XTR-PORT-CORRUPTION",
        PortErrorKind::Transport => "XTR-PORT-TRANSPORT",
        PortErrorKind::Internal => "XTR-PORT-INTERNAL",
    };
    ErrorCode::new(raw)
}

#[cfg(test)]
// Tests intentionally panic on invariant violations because the
// failure mode is "test failed", not "library panicked".
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert on invariants and may panic on violation"
)]
mod tests {
    use super::*;
    use crate::queries::GetStoreStatus;
    use std::collections::BTreeMap;
    use xtrace_domain::ProjectId;
    use xtrace_domain::Run;
    use xtrace_domain::RunId;
    use xtrace_domain::RunState;
    use xtrace_domain::ids::Id;

    /// Minimal in-memory repository used by the application tests.
    /// The repository is intentionally synchronous and deterministic
    /// so failures do not depend on the operating system scheduler.
    struct StubRepository {
        projects: std::sync::Mutex<BTreeMap<RepositoryFingerprint, Project>>,
        runs: std::sync::Mutex<BTreeMap<RunId, Run>>,
        init_receipts: std::sync::Mutex<BTreeMap<(String, String), StoredReceipt>>,
    }

    impl StubRepository {
        fn new() -> Self {
            Self {
                projects: std::sync::Mutex::new(BTreeMap::new()),
                runs: std::sync::Mutex::new(BTreeMap::new()),
                init_receipts: std::sync::Mutex::new(BTreeMap::new()),
            }
        }
    }

    impl ProjectRepository for StubRepository {
        fn initialize_project_with_receipt(
            &self,
            project: &Project,
            receipt: &StoredReceipt,
        ) -> Result<StoredReceipt, PortError> {
            let key = (receipt.command_kind.clone(), receipt.idempotency_key.clone());
            let mut receipts = self.init_receipts.lock().expect("stub lock");
            if let Some(existing) = receipts.get(&key) {
                if existing.project_id == receipt.project_id
                    && existing.input_digest == receipt.input_digest
                    && existing.receipt_json == receipt.receipt_json
                {
                    return Ok(existing.clone());
                }
                return Err(PortError::new(
                    PortErrorKind::Conflict,
                    "stub: init receipt mismatch",
                    CorrelationId::new(),
                ));
            }
            let mut projects = self.projects.lock().expect("stub lock");
            if projects.contains_key(&project.canonical_repo_hash) {
                return Err(PortError::new(
                    PortErrorKind::Conflict,
                    "stub: project exists without receipt",
                    CorrelationId::new(),
                ));
            }
            projects.insert(project.canonical_repo_hash.clone(), project.clone());
            receipts.insert(key, receipt.clone());
            Ok(receipt.clone())
        }

        fn insert_project(&self, project: &Project) -> Result<(), PortError> {
            let mut projects = self.projects.lock().expect("stub lock");
            if projects.contains_key(&project.canonical_repo_hash) {
                return Err(PortError::new(
                    PortErrorKind::AlreadyExists,
                    "stub: project exists",
                    CorrelationId::new(),
                ));
            }
            projects.insert(
                RepositoryFingerprint::try_from_canonical(project.canonical_repo_hash.as_str())
                    .expect("test stub inserts canonical fingerprint"),
                project.clone(),
            );
            Ok(())
        }

        fn load_project_by_fingerprint(
            &self,
            fingerprint: &RepositoryFingerprint,
        ) -> Result<Project, PortError> {
            let projects = self.projects.lock().expect("stub lock");
            projects.get(fingerprint).cloned().ok_or_else(|| {
                PortError::new(PortErrorKind::NotFound, "stub: not found", CorrelationId::new())
            })
        }

        fn load_project_by_id(&self, _project_id: ProjectId) -> Result<Project, PortError> {
            Err(PortError::new(
                PortErrorKind::NotFound,
                "stub: not implemented",
                CorrelationId::new(),
            ))
        }

        fn list_projects(&self) -> Result<Vec<Project>, PortError> {
            let projects = self.projects.lock().expect("stub lock");
            Ok(projects.values().cloned().collect())
        }

        fn touch_last_opened(
            &self,
            project_id: ProjectId,
            opened_at: WallTime,
        ) -> Result<(), PortError> {
            let mut projects = self.projects.lock().expect("stub lock");
            let project = projects
                .values_mut()
                .find(|project| project.id() == project_id)
                .ok_or_else(|| {
                    PortError::new(
                        PortErrorKind::NotFound,
                        "stub: project missing",
                        CorrelationId::new(),
                    )
                })?;
            project.last_opened_at = opened_at;
            Ok(())
        }

        fn insert_run(
            &self,
            _run: &Run,
            _project_id: ProjectId,
            _idempotency_key: &str,
        ) -> Result<(), PortError> {
            Ok(())
        }

        fn load_run(&self, _run_id: RunId) -> Result<Run, PortError> {
            Err(PortError::new(
                PortErrorKind::NotFound,
                "stub: not implemented",
                CorrelationId::new(),
            ))
        }

        fn update_run_state(
            &self,
            _run_id: RunId,
            _new_state: RunState,
            _finished_at: Option<WallTime>,
            _error_code: Option<&str>,
        ) -> Result<(), PortError> {
            Ok(())
        }

        fn allocate_run(
            &self,
            _project_id: ProjectId,
            _kind: RunKind,
            _requested_by: &str,
            _idempotency_key: &str,
            _requested_at: WallTime,
        ) -> Result<RunId, PortError> {
            let run_id = RunId::new();
            self.runs.lock().expect("stub lock").insert(
                run_id,
                Run {
                    id: run_id,
                    project_id: ProjectId::new(),
                    kind: RunKind::Scan,
                    state: RunState::Requested,
                    requested_at: WallTime::now(),
                    started_at: None,
                    finished_at: None,
                    requested_by: String::new(),
                    idempotency_key: String::new(),
                    error_code: None,
                },
            );
            Ok(run_id)
        }
    }

    /// Minimal in-memory idempotency store. The store keys receipts
    /// by `(command_kind, idempotency_key)` so the application
    /// facade's reuse-detection logic is exercised faithfully.
    struct StubIdempotencyStore {
        receipts: std::sync::Mutex<BTreeMap<(String, String), StoredReceipt>>,
    }

    impl StubIdempotencyStore {
        fn new() -> Self {
            Self { receipts: std::sync::Mutex::new(BTreeMap::new()) }
        }
    }

    impl IdempotencyStore for StubIdempotencyStore {
        fn lookup_receipt(
            &self,
            command_kind: &str,
            idempotency_key: &str,
        ) -> Result<Option<StoredReceipt>, PortError> {
            let guard = self.receipts.lock().expect("stub lock");
            Ok(guard.get(&(command_kind.to_string(), idempotency_key.to_string())).cloned())
        }

        fn record_receipt(&self, receipt: &StoredReceipt) -> Result<(), PortError> {
            let mut guard = self.receipts.lock().expect("stub lock");
            let key = (receipt.command_kind.clone(), receipt.idempotency_key.clone());
            if let Some(existing) = guard.get(&key) {
                if existing.input_digest != receipt.input_digest {
                    return Err(PortError::new(
                        PortErrorKind::AlreadyExists,
                        "stub: idempotency key reused",
                        CorrelationId::new(),
                    ));
                }
                return Ok(());
            }
            guard.insert(key, receipt.clone());
            Ok(())
        }
    }

    fn ctx() -> RequestContext {
        RequestContext::new("tester", WallTime::now())
    }

    fn app() -> Application<StubRepository, StubIdempotencyStore> {
        Application::new(StubRepository::new(), StubIdempotencyStore::new(), 1, 1, 0)
    }

    #[test]
    fn init_then_open_round_trip() {
        let app = app();
        let init = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: "idem-init".to_string(),
                    project_id: xtrace_domain::ProjectId::new(),
                }),
                &ctx(),
            )
            .expect("init");
        match init {
            CommandReceipt::ProjectInitialized { project_id, .. } => {
                assert!(!project_id.as_uuid().is_nil());
            }
            _ => panic!("expected ProjectInitialized receipt"),
        }
        let open = app
            .execute(
                Command::OpenProject(OpenProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    idempotency_key: "idem-open".to_string(),
                }),
                &ctx(),
            )
            .expect("open");
        match open {
            CommandReceipt::ProjectOpened { .. } => {}
            _ => panic!("expected ProjectOpened receipt"),
        }
    }

    #[test]
    fn init_replays_same_key_and_input() {
        let app = app();
        let first = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: "idem-replay".to_string(),
                    project_id: xtrace_domain::ProjectId::new(),
                }),
                &ctx(),
            )
            .expect("first init");
        let original_project_id = match &first {
            CommandReceipt::ProjectInitialized { project_id, .. } => *project_id,
            _ => panic!("first init must return a project receipt"),
        };
        let second = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: "idem-replay".to_string(),
                    project_id: original_project_id,
                }),
                &ctx(),
            )
            .expect("second init is a replay");
        match (&first, &second) {
            (
                CommandReceipt::ProjectInitialized { project_id: a, .. },
                CommandReceipt::ProjectInitialized { project_id: b, .. },
            ) => assert_eq!(a, b, "replayed receipt must carry the original project id"),
            _ => panic!("replay must return the original ProjectInitialized receipt"),
        }
    }

    #[test]
    fn init_conflicts_on_same_key_with_different_input() {
        let app = app();
        app.execute(
            Command::InitializeProject(InitializeProject {
                canonical_repo_path: "/tmp/example".to_string(),
                display_name: "Example".to_string(),
                idempotency_key: "idem-conflict".to_string(),
                project_id: xtrace_domain::ProjectId::new(),
            }),
            &ctx(),
        )
        .expect("first init");
        let err = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Renamed".to_string(),
                    idempotency_key: "idem-conflict".to_string(),
                    project_id: xtrace_domain::ProjectId::new(),
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Conflict);
    }

    #[test]
    fn init_requires_independent_receipt_for_existing_project() {
        let app = app();
        app.execute(
            Command::InitializeProject(InitializeProject {
                canonical_repo_path: "/tmp/example".to_string(),
                display_name: "Example".to_string(),
                idempotency_key: "idem-1".to_string(),
                project_id: xtrace_domain::ProjectId::new(),
            }),
            &ctx(),
        )
        .expect("first init");
        let err = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: "idem-2".to_string(),
                    project_id: xtrace_domain::ProjectId::new(),
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Conflict);
        assert!(err.message.contains("without independently persisted initialization proof"));
    }

    #[test]
    fn init_rejects_empty_path() {
        let err = app()
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: String::new(),
                    display_name: "Example".to_string(),
                    idempotency_key: "idem".to_string(),
                    project_id: xtrace_domain::ProjectId::new(),
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Validation);
    }

    #[test]
    fn init_rejects_empty_idempotency_key() {
        let err = app()
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: String::new(),
                    project_id: xtrace_domain::ProjectId::new(),
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Validation);
    }

    #[test]
    fn init_rejects_idempotency_key_with_control_characters() {
        let err = app()
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: "bad\nkey".to_string(),
                    project_id: xtrace_domain::ProjectId::new(),
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Validation);
    }

    #[test]
    fn init_rejects_oversized_idempotency_key() {
        let err = app()
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: "x".repeat(200),
                    project_id: xtrace_domain::ProjectId::new(),
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Validation);
    }

    #[test]
    fn init_rejects_empty_display_name() {
        let err = app()
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "   ".to_string(),
                    idempotency_key: "idem".to_string(),
                    project_id: xtrace_domain::ProjectId::new(),
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Validation);
    }

    #[test]
    fn init_rejects_path_with_nul() {
        let err = app()
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/bad\0path".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: "idem".to_string(),
                    project_id: xtrace_domain::ProjectId::new(),
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Validation);
    }

    #[test]
    fn status_reports_truthful_capabilities() {
        let app = app();
        let result = app.query(Query::GetStoreStatus(GetStoreStatus), &ctx()).expect("status");
        match result {
            QueryResult::StoreStatus(report) => {
                assert!(!report.capabilities.capture_supported);
                assert!(!report.capabilities.replay_supported);
                assert_eq!(report.capabilities.protocol_major, 1);
                assert_eq!(report.capabilities.protocol_minor, 0);
                assert_eq!(report.current_schema_version, 1);
            }
            _ => panic!("expected StoreStatus result"),
        }
    }

    #[test]
    fn open_rejects_unknown_fingerprint() {
        let err = app()
            .execute(
                Command::OpenProject(OpenProject {
                    canonical_repo_path: "/tmp/missing".to_string(),
                    idempotency_key: "idem".to_string(),
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::NotFound);
    }

    #[test]
    fn port_error_translation_covers_every_kind() {
        let correlation = CorrelationId::new();
        let request = CorrelationId::new();
        for kind in [
            PortErrorKind::Validation,
            PortErrorKind::AlreadyExists,
            PortErrorKind::NotFound,
            PortErrorKind::Conflict,
            PortErrorKind::Compatibility,
            PortErrorKind::Resource,
            PortErrorKind::Corruption,
            PortErrorKind::Transport,
            PortErrorKind::Internal,
        ] {
            let err = PortError::new(kind, "message", correlation);
            let app_error = port_error_to_app_error(err, request);
            // Every `PortErrorKind` maps to a stable `XTR-PORT-*` code.
            assert!(
                app_error.code.as_str().starts_with("XTR-PORT-"),
                "missing port code prefix for {kind:?}"
            );
            assert_eq!(app_error.correlation_id, request);
        }
    }

    #[test]
    fn canonical_input_digest_is_stable_and_input_sensitive() {
        let a = canonical_input_digest("initialize_project", "/tmp/example", "Example");
        let b = canonical_input_digest("initialize_project", "/tmp/example", "Example");
        assert_eq!(a, b);
        let c = canonical_input_digest("initialize_project", "/tmp/example", "Different");
        assert_ne!(a, c);
        let d = canonical_input_digest("open_project", "/tmp/example", "Example");
        assert_ne!(a, d);
    }

    #[test]
    fn replay_lookup_propagates_correlation_id_on_infrastructure_failure() {
        // A port failure during idempotency lookup must reach the
        // boundary as an `AppError` carrying the request's
        // correlation ID so diagnostics can stitch the request to
        // the storage-side log line.
        struct TransportFailStub;
        impl ProjectRepository for TransportFailStub {
            fn initialize_project_with_receipt(
                &self,
                _: &Project,
                _: &StoredReceipt,
            ) -> Result<StoredReceipt, PortError> {
                Err(PortError::new(PortErrorKind::Transport, "disk on fire", CorrelationId::new()))
            }
            fn insert_project(&self, _: &Project) -> Result<(), PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
            fn load_project_by_fingerprint(
                &self,
                _: &RepositoryFingerprint,
            ) -> Result<Project, PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
            fn load_project_by_id(&self, _: ProjectId) -> Result<Project, PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
            fn list_projects(&self) -> Result<Vec<Project>, PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
            fn touch_last_opened(&self, _: ProjectId, _: WallTime) -> Result<(), PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
            fn insert_run(&self, _: &Run, _: ProjectId, _: &str) -> Result<(), PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
            fn load_run(&self, _: RunId) -> Result<Run, PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
            fn update_run_state(
                &self,
                _: RunId,
                _: RunState,
                _: Option<WallTime>,
                _: Option<&str>,
            ) -> Result<(), PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
            fn allocate_run(
                &self,
                _: ProjectId,
                _: RunKind,
                _: &str,
                _: &str,
                _: WallTime,
            ) -> Result<RunId, PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
        }
        struct TransportIdem;
        impl IdempotencyStore for TransportIdem {
            fn lookup_receipt(&self, _: &str, _: &str) -> Result<Option<StoredReceipt>, PortError> {
                Err(PortError::new(PortErrorKind::Transport, "disk on fire", CorrelationId::new()))
            }
            fn record_receipt(&self, _: &StoredReceipt) -> Result<(), PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
        }
        let request = CorrelationId::new();
        let app: Application<TransportFailStub, TransportIdem> =
            Application::new(TransportFailStub, TransportIdem, 1, 1, 0);
        let mut context = RequestContext::new("tester", WallTime::now());
        context.correlation_id = request;
        let err = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: "idem".to_string(),
                    project_id: ProjectId::new(),
                }),
                &context,
            )
            .unwrap_err();
        assert_eq!(err.correlation_id, request);
        assert_eq!(err.category, ErrorCategory::Transport);
    }

    #[test]
    fn port_error_translation_preserves_correlation_id() {
        let original = CorrelationId::new();
        let request = CorrelationId::new();
        let port = PortError::new(PortErrorKind::Corruption, "schema check failed", original)
            .with_source("underlying rusqlite error");
        let app_error = port_error_to_app_error(port, request);
        // The request correlation ID reaches the boundary, not the
        // infrastructure-generated one.
        assert_eq!(app_error.correlation_id, request);
        assert_eq!(app_error.category, ErrorCategory::Corruption);
        // The infrastructure correlation is preserved as a diagnostic
        // detail so a future slice can stitch request and store logs.
        assert_eq!(
            app_error.details.get("infrastructure_correlation_id").map(|scalar| match scalar {
                xtrace_domain::SafeScalar::String(s) => s.clone(),
                _ => String::new(),
            }),
            Some(original.to_string()),
        );
        assert_eq!(
            app_error.details.get("source").map(|scalar| match scalar {
                xtrace_domain::SafeScalar::String(s) => s.clone(),
                _ => String::new(),
            }),
            Some("underlying rusqlite error".to_string()),
        );
    }

    /// Project repository stub whose `insert_project` returns a
    /// `PortErrorKind::Corruption` failure carrying the supplied
    /// infra correlation ID. Other methods are guarded as "not
    /// reached" so the application facade's early returns do not
    /// silently succeed.
    struct InsertFailureRepo(CorrelationId);
    impl ProjectRepository for InsertFailureRepo {
        fn initialize_project_with_receipt(
            &self,
            _: &Project,
            _: &StoredReceipt,
        ) -> Result<StoredReceipt, PortError> {
            Err(PortError::new(PortErrorKind::Corruption, "insert failed", self.0))
        }
        fn insert_project(&self, _: &Project) -> Result<(), PortError> {
            Err(PortError::new(PortErrorKind::Corruption, "insert failed", self.0))
        }
        fn load_project_by_fingerprint(
            &self,
            _: &RepositoryFingerprint,
        ) -> Result<Project, PortError> {
            Err(PortError::new(PortErrorKind::NotFound, "not reached", CorrelationId::new()))
        }
        fn load_project_by_id(&self, _: ProjectId) -> Result<Project, PortError> {
            Err(PortError::new(PortErrorKind::NotFound, "not reached", CorrelationId::new()))
        }
        fn list_projects(&self) -> Result<Vec<Project>, PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
        fn touch_last_opened(&self, _: ProjectId, _: WallTime) -> Result<(), PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
        fn insert_run(&self, _: &Run, _: ProjectId, _: &str) -> Result<(), PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
        fn load_run(&self, _: RunId) -> Result<Run, PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
        fn update_run_state(
            &self,
            _: RunId,
            _: RunState,
            _: Option<WallTime>,
            _: Option<&str>,
        ) -> Result<(), PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
        fn allocate_run(
            &self,
            _: ProjectId,
            _: RunKind,
            _: &str,
            _: &str,
            _: WallTime,
        ) -> Result<RunId, PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
    }

    #[test]
    fn init_repository_failure_preserves_request_correlation_id() {
        let infra = CorrelationId::new();
        let request = CorrelationId::new();
        let app: Application<InsertFailureRepo, StubIdempotencyStore> =
            Application::new(InsertFailureRepo(infra), StubIdempotencyStore::new(), 1, 1, 0);
        let mut context = RequestContext::new("tester", WallTime::now());
        context.correlation_id = request;
        let err = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: "idem".to_string(),
                    project_id: ProjectId::new(),
                }),
                &context,
            )
            .unwrap_err();
        // The request correlation reaches the boundary verbatim.
        assert_eq!(err.correlation_id, request);
        assert_eq!(err.category, ErrorCategory::Corruption);
        // The infrastructure correlation is preserved as a diagnostic
        // detail.
        assert_eq!(
            err.details.get("infrastructure_correlation_id").map(|scalar| match scalar {
                xtrace_domain::SafeScalar::String(s) => s.clone(),
                _ => String::new(),
            }),
            Some(infra.to_string()),
        );
        // Empty source must not appear as a detail.
        let has_empty_source = matches!(
            err.details.get("source"),
            Some(xtrace_domain::SafeScalar::String(s)) if s.is_empty()
        );
        assert!(!has_empty_source, "empty source must not be attached as a detail");
    }

    /// Project repository stub whose `touch_last_opened` returns
    /// a `PortErrorKind::Transport` failure carrying the supplied
    /// infra correlation ID. `load_project_by_fingerprint` returns
    /// a stub project so the open path proceeds to the touch step.
    struct TouchFailureRepo(CorrelationId);
    impl ProjectRepository for TouchFailureRepo {
        fn insert_project(&self, _: &Project) -> Result<(), PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
        fn load_project_by_fingerprint(
            &self,
            _: &RepositoryFingerprint,
        ) -> Result<Project, PortError> {
            Ok(Project {
                id: ProjectId::new(),
                canonical_repo_hash: RepositoryFingerprint::from_canonical_path("/tmp/example"),
                display_name: "Example".to_string(),
                created_at: WallTime::now(),
                last_opened_at: WallTime::now(),
                config_schema_version: 1,
                effective_config_hash: String::new(),
                active_capture_policy_id: None,
                active_redaction_policy_id: None,
            })
        }
        fn load_project_by_id(&self, _: ProjectId) -> Result<Project, PortError> {
            Err(PortError::new(PortErrorKind::NotFound, "not reached", CorrelationId::new()))
        }
        fn list_projects(&self) -> Result<Vec<Project>, PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
        fn touch_last_opened(&self, _: ProjectId, _: WallTime) -> Result<(), PortError> {
            Err(PortError::new(PortErrorKind::Transport, "touch failed", self.0))
        }
        fn insert_run(&self, _: &Run, _: ProjectId, _: &str) -> Result<(), PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
        fn load_run(&self, _: RunId) -> Result<Run, PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
        fn update_run_state(
            &self,
            _: RunId,
            _: RunState,
            _: Option<WallTime>,
            _: Option<&str>,
        ) -> Result<(), PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
        fn allocate_run(
            &self,
            _: ProjectId,
            _: RunKind,
            _: &str,
            _: &str,
            _: WallTime,
        ) -> Result<RunId, PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
    }

    #[test]
    fn open_touch_failure_preserves_request_correlation_id() {
        let infra = CorrelationId::new();
        let request = CorrelationId::new();
        let app: Application<TouchFailureRepo, StubIdempotencyStore> =
            Application::new(TouchFailureRepo(infra), StubIdempotencyStore::new(), 1, 1, 0);
        let mut context = RequestContext::new("tester", WallTime::now());
        context.correlation_id = request;
        let err = app
            .execute(
                Command::OpenProject(OpenProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    idempotency_key: "idem".to_string(),
                }),
                &context,
            )
            .unwrap_err();
        assert_eq!(err.correlation_id, request);
        assert_eq!(err.category, ErrorCategory::Transport);
        assert_eq!(
            err.details.get("infrastructure_correlation_id").map(|scalar| match scalar {
                xtrace_domain::SafeScalar::String(s) => s.clone(),
                _ => String::new(),
            }),
            Some(infra.to_string()),
        );
    }

    /// Project repository stub whose `list_projects` returns a
    /// `PortErrorKind::Resource` failure carrying the supplied
    /// infra correlation ID.
    struct ListFailureRepo(CorrelationId);
    impl ProjectRepository for ListFailureRepo {
        fn insert_project(&self, _: &Project) -> Result<(), PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
        fn load_project_by_fingerprint(
            &self,
            _: &RepositoryFingerprint,
        ) -> Result<Project, PortError> {
            Err(PortError::new(PortErrorKind::NotFound, "not reached", CorrelationId::new()))
        }
        fn load_project_by_id(&self, _: ProjectId) -> Result<Project, PortError> {
            Err(PortError::new(PortErrorKind::NotFound, "not reached", CorrelationId::new()))
        }
        fn list_projects(&self) -> Result<Vec<Project>, PortError> {
            Err(PortError::new(PortErrorKind::Resource, "list failed", self.0))
        }
        fn touch_last_opened(&self, _: ProjectId, _: WallTime) -> Result<(), PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
        fn insert_run(&self, _: &Run, _: ProjectId, _: &str) -> Result<(), PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
        fn load_run(&self, _: RunId) -> Result<Run, PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
        fn update_run_state(
            &self,
            _: RunId,
            _: RunState,
            _: Option<WallTime>,
            _: Option<&str>,
        ) -> Result<(), PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
        fn allocate_run(
            &self,
            _: ProjectId,
            _: RunKind,
            _: &str,
            _: &str,
            _: WallTime,
        ) -> Result<RunId, PortError> {
            Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
        }
    }

    #[test]
    fn status_list_failure_preserves_request_correlation_id() {
        let infra = CorrelationId::new();
        let request = CorrelationId::new();
        let app: Application<ListFailureRepo, StubIdempotencyStore> =
            Application::new(ListFailureRepo(infra), StubIdempotencyStore::new(), 1, 1, 0);
        let mut context = RequestContext::new("tester", WallTime::now());
        context.correlation_id = request;
        let err = app.query(Query::GetStoreStatus(GetStoreStatus), &context).unwrap_err();
        assert_eq!(err.correlation_id, request);
        assert_eq!(err.category, ErrorCategory::Resource);
        assert_eq!(
            err.details.get("infrastructure_correlation_id").map(|scalar| match scalar {
                xtrace_domain::SafeScalar::String(s) => s.clone(),
                _ => String::new(),
            }),
            Some(infra.to_string()),
        );
    }

    /// Idempotency store stub whose `record_receipt` always fails
    /// with a `PortErrorKind::Internal` carrying a distinct
    /// infrastructure correlation ID.
    struct RecordFailureIdem(CorrelationId);
    impl IdempotencyStore for RecordFailureIdem {
        fn lookup_receipt(&self, _: &str, _: &str) -> Result<Option<StoredReceipt>, PortError> {
            Ok(None)
        }
        fn record_receipt(&self, _: &StoredReceipt) -> Result<(), PortError> {
            Err(PortError::new(PortErrorKind::Internal, "record failed", self.0))
        }
    }

    #[test]
    fn idempotency_record_failure_preserves_request_correlation_id() {
        let infra = CorrelationId::new();
        let request = CorrelationId::new();
        let app: Application<StubRepository, RecordFailureIdem> =
            Application::new(StubRepository::new(), RecordFailureIdem(infra), 1, 1, 0);
        let mut context = RequestContext::new("tester", WallTime::now());
        context.correlation_id = request;
        let err = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: "idem".to_string(),
                    project_id: ProjectId::new(),
                }),
                &context,
            )
            .unwrap_err();
        assert_eq!(err.correlation_id, request);
        assert_eq!(err.category, ErrorCategory::Internal);
        assert_eq!(
            err.details.get("infrastructure_correlation_id").map(|scalar| match scalar {
                xtrace_domain::SafeScalar::String(s) => s.clone(),
                _ => String::new(),
            }),
            Some(infra.to_string()),
        );
    }

    #[test]
    fn load_lookup_propagates_correlation_id_on_infrastructure_failure() {
        // `load_project_by_fingerprint` failure (e.g. a SQL
        // `Corruption` report) must surface as a typed
        // `Corruption` `AppError` carrying the request correlation
        // ID rather than an infrastructure-generated one.
        struct LoadCorruptionRepo(CorrelationId);
        impl ProjectRepository for LoadCorruptionRepo {
            fn insert_project(&self, _: &Project) -> Result<(), PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
            fn load_project_by_fingerprint(
                &self,
                _: &RepositoryFingerprint,
            ) -> Result<Project, PortError> {
                Err(PortError::new(PortErrorKind::Corruption, "schema corrupt", self.0))
            }
            fn load_project_by_id(&self, _: ProjectId) -> Result<Project, PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
            fn list_projects(&self) -> Result<Vec<Project>, PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
            fn touch_last_opened(&self, _: ProjectId, _: WallTime) -> Result<(), PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
            fn insert_run(&self, _: &Run, _: ProjectId, _: &str) -> Result<(), PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
            fn load_run(&self, _: RunId) -> Result<Run, PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
            fn update_run_state(
                &self,
                _: RunId,
                _: RunState,
                _: Option<WallTime>,
                _: Option<&str>,
            ) -> Result<(), PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
            fn allocate_run(
                &self,
                _: ProjectId,
                _: RunKind,
                _: &str,
                _: &str,
                _: WallTime,
            ) -> Result<RunId, PortError> {
                Err(PortError::new(PortErrorKind::Internal, "not reached", CorrelationId::new()))
            }
        }
        let infra = CorrelationId::new();
        let request = CorrelationId::new();
        let app: Application<LoadCorruptionRepo, StubIdempotencyStore> =
            Application::new(LoadCorruptionRepo(infra), StubIdempotencyStore::new(), 1, 1, 0);
        let mut context = RequestContext::new("tester", WallTime::now());
        context.correlation_id = request;
        let err = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: "idem".to_string(),
                    project_id: ProjectId::new(),
                }),
                &context,
            )
            .unwrap_err();
        assert_eq!(err.correlation_id, request);
        assert_eq!(err.category, ErrorCategory::Corruption);
        assert_eq!(
            err.details.get("infrastructure_correlation_id").map(|scalar| match scalar {
                xtrace_domain::SafeScalar::String(s) => s.clone(),
                _ => String::new(),
            }),
            Some(infra.to_string()),
        );
    }
}
