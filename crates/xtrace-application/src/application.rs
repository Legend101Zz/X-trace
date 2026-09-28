//! Application facade.
//!
//! The [`Application`] type is the single entry point for clients
//! (CLI, TUI, daemon HTTP handlers). It owns the [`RequestContext`]
//! factory, validates incoming commands and queries, orchestrates the
//! relevant ports, and translates internal failures into typed
//! [`AppError`] values.
//!
//! The facade is intentionally generic over a single repository port
//! in Slice 1A. Future slices parameterize over additional ports
//! without breaking the public signature.

use std::sync::Arc;

use xtrace_domain::{
    AppError, CorrelationId, ErrorCategory, ErrorCode, Project, ProjectId, RepositoryFingerprint,
    RetryAdvice, RunKind, WallTime,
};

use crate::commands::{Command, CommandReceipt, InitializeProject, OpenProject, ProjectSnapshot};
use crate::error::{PortError, PortErrorKind};
use crate::ports::ProjectRepository;
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
pub struct Application<R: ProjectRepository> {
    repository: Arc<R>,
    /// Schema version this binary initializes a fresh store with.
    target_schema_version: u32,
    /// XTP-Agent protocol major version this binary speaks.
    protocol_major: u32,
    /// XTP-Agent protocol minor version this binary speaks.
    protocol_minor: u32,
}

impl<R: ProjectRepository> Application<R> {
    /// Constructs a new application facade over the supplied port
    /// implementation.
    #[must_use]
    pub fn new(
        repository: R,
        target_schema_version: u32,
        protocol_major: u32,
        protocol_minor: u32,
    ) -> Self {
        Self {
            repository: Arc::new(repository),
            target_schema_version,
            protocol_major,
            protocol_minor,
        }
    }

    /// Executes a single command and returns its receipt.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] for every validation or port failure.
    /// Validation failures are surfaced as
    /// [`ErrorCategory::Validation`]; port failures are translated
    /// into the matching [`ErrorCategory`] before crossing the
    /// boundary.
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
    /// Returns [`AppError`] for validation or port failures.
    pub fn query(&self, query: Query, ctx: &RequestContext) -> Result<QueryResult, AppError> {
        match query {
            Query::GetProject(query) => self.get_project(query, ctx),
            Query::GetStoreStatus(_) => self.get_store_status(ctx),
        }
    }

    /// Convenience helper that allocates a [`RunId`] through the port
    /// without exposing the port directly.
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] when the project is missing or the port
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
            .map_err(port_error_to_app_error)?;
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
        if self.repository.load_project_by_fingerprint(&fingerprint).is_ok() {
            return Err(existing_project_error(&fingerprint, ctx.correlation_id));
        }
        let project = Project {
            id: ProjectId::new(),
            canonical_repo_hash: fingerprint.clone(),
            display_name: cmd.display_name,
            created_at: ctx.requested_at,
            last_opened_at: ctx.requested_at,
            config_schema_version: 1,
            effective_config_hash: String::new(),
            active_capture_policy_id: None,
            active_redaction_policy_id: None,
        };
        self.repository.insert_project(&project).map_err(port_error_to_app_error)?;
        Ok(CommandReceipt::ProjectInitialized {
            project_id: project.id,
            fingerprint,
            idempotency_key: cmd.idempotency_key,
        })
    }

    fn open_project(
        &self,
        cmd: OpenProject,
        ctx: &RequestContext,
    ) -> Result<CommandReceipt, AppError> {
        validate_canonical_repo_path(&cmd.canonical_repo_path, ctx.correlation_id)?;
        validate_idempotency_key(&cmd.idempotency_key, ctx.correlation_id)?;
        let fingerprint = RepositoryFingerprint::from_canonical_path(&cmd.canonical_repo_path);
        let project = self
            .repository
            .load_project_by_fingerprint(&fingerprint)
            .map_err(port_error_to_app_error)?;
        self.repository
            .touch_last_opened(project.id(), ctx.requested_at)
            .map_err(port_error_to_app_error)?;
        Ok(CommandReceipt::ProjectOpened {
            project_id: project.id(),
            idempotency_key: cmd.idempotency_key,
        })
    }

    fn get_project(
        &self,
        query: GetProject,
        ctx: &RequestContext,
    ) -> Result<QueryResult, AppError> {
        validate_canonical_repo_path(&query.canonical_repo_path, ctx.correlation_id)?;
        let fingerprint = RepositoryFingerprint::from_canonical_path(&query.canonical_repo_path);
        let project = self
            .repository
            .load_project_by_fingerprint(&fingerprint)
            .map_err(port_error_to_app_error)?;
        Ok(QueryResult::Project(ProjectSnapshot::new(project)))
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
        let projects = self
            .repository
            .list_projects()
            .map_err(port_error_to_app_error)?
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

fn existing_project_error(
    fingerprint: &RepositoryFingerprint,
    correlation_id: CorrelationId,
) -> AppError {
    AppError::new(
        xtrace_domain::codes::PROJECT_ALREADY_EXISTS.clone(),
        ErrorCategory::Conflict,
        "a project is already registered for this repository",
        RetryAdvice::None,
        correlation_id,
    )
    .with_detail("fingerprint", fingerprint.as_str().to_string())
}

/// Translates an internal [`PortError`] into the public [`AppError`]
/// contract. The mapping is total so port authors cannot accidentally
/// leak a variant through the boundary.
fn port_error_to_app_error(err: PortError) -> AppError {
    let mut builder = AppError::new(
        port_code(err.kind()),
        port_category(err.kind()),
        err.message(),
        port_retry(err.kind()),
        err.correlation_id(),
    );
    if let Some(source) = err.source() {
        builder = builder.with_detail("source", source.to_string());
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
    use xtrace_domain::ids::Id as _;
    use xtrace_domain::ProjectId;
    use xtrace_domain::Run;
    use xtrace_domain::RunId;
    use xtrace_domain::RunState;

    /// Minimal in-memory repository used by the application tests.
    /// The repository is intentionally synchronous and deterministic
    /// so failures do not depend on the operating system scheduler.
    struct StubRepository {
        projects: std::sync::Mutex<BTreeMap<RepositoryFingerprint, Project>>,
        runs: std::sync::Mutex<BTreeMap<RunId, Run>>,
    }

    impl StubRepository {
        fn new() -> Self {
            Self {
                projects: std::sync::Mutex::new(BTreeMap::new()),
                runs: std::sync::Mutex::new(BTreeMap::new()),
            }
        }
    }

    impl ProjectRepository for StubRepository {
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
                RepositoryFingerprint::from_canonical(project.canonical_repo_hash.as_str()),
                project.clone(),
            );
            Ok(())
        }

        fn load_project_by_fingerprint(
            &self,
            fingerprint: &RepositoryFingerprint,
        ) -> Result<Project, PortError> {
            let projects = self.projects.lock().expect("stub lock");
            projects
                .get(fingerprint)
                .cloned()
                .ok_or_else(|| {
                    PortError::new(
                        PortErrorKind::NotFound,
                        "stub: not found",
                        CorrelationId::new(),
                    )
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

    fn ctx() -> RequestContext {
        RequestContext::new("tester", WallTime::now())
    }

    #[test]
    fn init_then_open_round_trip() {
        let repo = StubRepository::new();
        let app = Application::new(repo, 1, 1, 0);
        let init = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: "idem-init".to_string(),
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
    fn init_rejects_duplicate_fingerprint() {
        let repo = StubRepository::new();
        let app = Application::new(repo, 1, 1, 0);
        app.execute(
            Command::InitializeProject(InitializeProject {
                canonical_repo_path: "/tmp/example".to_string(),
                display_name: "Example".to_string(),
                idempotency_key: "idem-1".to_string(),
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
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.code, *xtrace_domain::codes::PROJECT_ALREADY_EXISTS);
        assert_eq!(err.category, ErrorCategory::Conflict);
    }

    #[test]
    fn init_rejects_empty_path() {
        let repo = StubRepository::new();
        let app = Application::new(repo, 1, 1, 0);
        let err = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: String::new(),
                    display_name: "Example".to_string(),
                    idempotency_key: "idem".to_string(),
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Validation);
    }

    #[test]
    fn init_rejects_empty_idempotency_key() {
        let repo = StubRepository::new();
        let app = Application::new(repo, 1, 1, 0);
        let err = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: String::new(),
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Validation);
    }

    #[test]
    fn init_rejects_idempotency_key_with_control_characters() {
        let repo = StubRepository::new();
        let app = Application::new(repo, 1, 1, 0);
        let err = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: "bad\nkey".to_string(),
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Validation);
    }

    #[test]
    fn init_rejects_oversized_idempotency_key() {
        let repo = StubRepository::new();
        let app = Application::new(repo, 1, 1, 0);
        let err = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: "x".repeat(200),
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Validation);
    }

    #[test]
    fn init_rejects_empty_display_name() {
        let repo = StubRepository::new();
        let app = Application::new(repo, 1, 1, 0);
        let err = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/example".to_string(),
                    display_name: "   ".to_string(),
                    idempotency_key: "idem".to_string(),
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Validation);
    }

    #[test]
    fn init_rejects_path_with_nul() {
        let repo = StubRepository::new();
        let app = Application::new(repo, 1, 1, 0);
        let err = app
            .execute(
                Command::InitializeProject(InitializeProject {
                    canonical_repo_path: "/tmp/bad\0path".to_string(),
                    display_name: "Example".to_string(),
                    idempotency_key: "idem".to_string(),
                }),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.category, ErrorCategory::Validation);
    }

    #[test]
    fn status_reports_truthful_capabilities() {
        let repo = StubRepository::new();
        let app = Application::new(repo, 1, 1, 0);
        let result = app
            .query(Query::GetStoreStatus(GetStoreStatus), &ctx())
            .expect("status");
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
        let repo = StubRepository::new();
        let app = Application::new(repo, 1, 1, 0);
        let err = app
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
            let app_error = port_error_to_app_error(err);
            // Every `PortErrorKind` maps to a stable `XTR-PORT-*` code.
            assert!(
                app_error.code.as_str().starts_with("XTR-PORT-"),
                "missing port code prefix for {kind:?}"
            );
        }
    }
}
