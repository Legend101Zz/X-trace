//! CLI subcommand definitions and dispatch.
//!
//! Each subcommand parses its own arguments, builds the corresponding
//! application [`Command`] or [`Query`], invokes the application
//! facade, and renders the result. The dispatcher owns no policy; the
//! application facade is the single source of truth for what the
//! CLI is allowed to do.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use serde::Serialize;
use xtrace_application::{
    Application, Command, GetProject, GetStoreStatus, InitializeProject, ListObservedEndpoints,
    ListOperationRecordings, ListRecordings, ListUnmatchedRecordings, ObservedEndpointQueryService,
    OpenProject, Query, QueryResult, RecordingQueryService, RequestContext, ShowRecording,
};
use xtrace_domain::{
    AppError, CorrelationId, ErrorCategory, ErrorCode, OperationId, RecordingId, RetryAdvice,
    WallTime,
};
use xtrace_private_storage::AdmittedPrivateRoot;
use xtrace_store::{CURRENT_SCHEMA_VERSION, SqliteIdempotencyStore, SqliteProjectRepository};
use xtrace_store::{SqliteRecordingReader, SqliteStore, StoreErrorKind};

use crate::error::CliError;
use crate::output::write_success;
use crate::paths::{RepositoryPointer, UserDataPaths};

/// Top-level subcommand surface parsed by [`clap`].
#[derive(Clone, Debug, Subcommand)]
pub enum XtraceCommand {
    /// Initialize a new X-trace project for a repository.
    Init {
        /// Path to the repository root.
        #[arg(long = "project-dir", value_name = "DIR")]
        project_dir: PathBuf,
        /// Display name shown in `xtrace status` and the UI surfaces.
        #[arg(long = "display-name", value_name = "NAME", default_value = "")]
        display_name: String,
        /// Idempotency key. Repeated runs with the same key and the
        /// same canonical input return the original receipt.
        #[arg(long = "idempotency-key", value_name = "KEY", default_value = "")]
        idempotency_key: String,
    },
    /// Open an existing X-trace project.
    Open {
        /// Path to the repository root.
        #[arg(long = "project-dir", value_name = "DIR")]
        project_dir: PathBuf,
        /// Idempotency key.
        #[arg(long = "idempotency-key", value_name = "KEY", default_value = "")]
        idempotency_key: String,
        /// Start the experimental foreground browser viewer instead of opening the project record.
        #[arg(long)]
        viewer: bool,
        /// Print the viewer URL without launching a browser (requires --viewer).
        #[arg(long, requires = "viewer")]
        no_browser: bool,
    },
    /// Emit a machine-readable status report for the local store.
    Status {
        /// Path to the repository root.
        #[arg(long = "project-dir", value_name = "DIR")]
        project_dir: PathBuf,
    },
    /// Read persisted recordings through the verified local store path.
    Recording {
        #[command(subcommand)]
        command: RecordingCommand,
    },
    /// Read observed endpoints and their linked recordings.
    Endpoint {
        #[command(subcommand)]
        command: EndpointCommand,
    },
    /// Run the Unix-only foreground, project-scoped XTP recording ingress daemon.
    ///
    /// This command durably writes sealed event segments and retains the
    /// protocol's `Staged` ACK behavior. It does not launch a language adapter
    /// or claim that one is available.
    ///
    /// SIGINT and SIGTERM request graceful shutdown and wait for in-flight
    /// daemon work. SIGKILL cannot run cleanup; the next daemon start that
    /// obtains the project lock removes only recognized stale runtime files.
    /// The current bootstrap artifact has no time-based expiry; expiry is
    /// deferred, and a SIGKILL may leave it until the next start.
    Daemon {
        /// Path to the initialized repository root.
        #[arg(long = "project-dir", value_name = "DIR")]
        project_dir: PathBuf,
    },
    /// Attach experimental standard Java capture to one already-running JVM.
    #[cfg(unix)]
    Attach {
        /// Path to the initialized repository root.
        #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
        project_dir: PathBuf,
        /// Explicit target JVM PID. Without it, an interactive terminal must select a listed row.
        #[arg(long, value_name = "PID")]
        pid: Option<u32>,
        /// Explicit unsigned development pack. Publisher authenticity is not verified.
        #[arg(long = "java-pack", value_name = "DIR", required = true)]
        java_pack: PathBuf,
        /// Emit one JSON result after a successful attach.
        #[arg(long)]
        json: bool,
    },
    /// Launch a direct Java process with experimental capture enabled.
    Run {
        /// Path to the initialized repository root.
        #[arg(long = "project-dir", value_name = "DIR")]
        project_dir: PathBuf,
        /// Path to the built X-trace Java agent JAR.
        #[arg(long = "java-agent", value_name = "PATH", conflicts_with_all = ["node_adapter", "node_mode"], required_unless_present = "node_adapter")]
        java_agent: Option<PathBuf>,
        /// Path to the built Node adapter dist directory.
        #[arg(
            long = "node-adapter",
            value_name = "DIR",
            conflicts_with = "java_agent",
            required_unless_present = "java_agent",
            requires = "node_mode"
        )]
        node_adapter: Option<PathBuf>,
        /// Explicit Node module mode. Required with --node-adapter.
        #[arg(
            long = "node-mode",
            value_name = "cjs|esm",
            requires = "node_adapter",
            conflicts_with = "java_agent"
        )]
        node_mode: Option<String>,
        /// Explicitly opt into the finite observed-endpoint rule.
        #[arg(long = "observed-endpoint-policy")]
        observed_endpoint_policy: Option<String>,
        /// Stable, run-scoped application component (must be paired with --binding-key).
        #[arg(long = "application-component", requires = "binding_key")]
        application_component: Option<String>,
        /// Stable, run-scoped transport binding (must be paired with --application-component).
        #[arg(long = "binding-key", requires = "application_component")]
        binding_key: Option<String>,
        /// Java executable followed by its original arguments.
        #[arg(last = true, required = true, num_args = 1.., allow_hyphen_values = true)]
        command: Vec<OsString>,
    },
}

/// Read-only recording query commands.
#[derive(Clone, Debug, Subcommand)]
pub enum RecordingCommand {
    /// List a stable, bounded page of recordings.
    List {
        /// Path to the initialized repository root.
        #[arg(long = "project-dir", value_name = "DIR")]
        project_dir: PathBuf,
        /// Maximum rows in this page.
        #[arg(long, value_name = "N", allow_hyphen_values = true)]
        limit: Option<String>,
        /// Exclusive recording ID cursor from the previous page.
        #[arg(long, value_name = "RECORDING_ID", allow_hyphen_values = true)]
        after: Option<String>,
        /// List only unmatched and legacy recordings.
        #[arg(long)]
        unmatched: bool,
        /// Versioned cursor returned by a previous unmatched page.
        #[arg(long, value_name = "CURSOR", allow_hyphen_values = true)]
        cursor: Option<String>,
    },
    /// Show a bounded, ordered Linear event window.
    Show {
        /// Path to the initialized repository root.
        #[arg(long = "project-dir", value_name = "DIR")]
        project_dir: PathBuf,
        /// Recording ID to read.
        recording_id: RecordingId,
        /// Maximum events in the returned window.
        #[arg(long, default_value_t = xtrace_application::DEFAULT_RECORDING_EVENT_LIMIT)]
        limit: u32,
        /// Versioned cursor returned by a previous show response.
        #[arg(long, value_name = "CURSOR", allow_hyphen_values = true)]
        cursor: Option<String>,
    },
}

/// Read-only observed endpoint query commands.
#[derive(Clone, Debug, Subcommand)]
pub enum EndpointCommand {
    /// List the project's bounded observed endpoint catalog.
    List {
        /// Path to the initialized repository root.
        #[arg(long = "project-dir", value_name = "DIR")]
        project_dir: PathBuf,
        /// Maximum number of endpoints in this page.
        #[arg(long, value_name = "N", allow_hyphen_values = true)]
        limit: Option<String>,
        /// Opaque continuation returned by a previous endpoint page.
        #[arg(long, value_name = "CURSOR", allow_hyphen_values = true)]
        cursor: Option<String>,
    },
    /// List bounded recordings linked to one observed operation.
    Recordings {
        /// Canonical UUIDv7 operation ID.
        #[arg(allow_hyphen_values = true)]
        operation_id: String,
        /// Path to the initialized repository root.
        #[arg(long = "project-dir", value_name = "DIR")]
        project_dir: PathBuf,
        /// Maximum number of recordings in this page.
        #[arg(long, value_name = "N", allow_hyphen_values = true)]
        limit: Option<String>,
        /// Opaque continuation returned by a previous recording page.
        #[arg(long, value_name = "CURSOR", allow_hyphen_values = true)]
        cursor: Option<String>,
    },
}

/// Dispatches the supplied subcommand and writes the result to
/// stdout. Errors propagate as [`CliError`] so the binary entry
/// point can render them.
pub async fn run(command: XtraceCommand) -> Result<i32, CliError> {
    match command {
        XtraceCommand::Init { project_dir, display_name, idempotency_key } => {
            init(project_dir, display_name, idempotency_key, &crate::paths::read_env_path)
                .map(|()| 0)
        }
        XtraceCommand::Open { project_dir, idempotency_key, viewer, no_browser } => {
            if viewer {
                crate::viewer::run(project_dir, no_browser).await.map(|()| 0)
            } else {
                open(project_dir, idempotency_key, &crate::paths::read_env_path).map(|()| 0)
            }
        }
        XtraceCommand::Status { project_dir } => {
            status(project_dir, &crate::paths::read_env_path).map(|()| 0)
        }
        XtraceCommand::Recording { command } => {
            recording(command, &crate::paths::read_env_path).map(|()| 0)
        }
        XtraceCommand::Endpoint { command } => {
            endpoint(command, &crate::paths::read_env_path).map(|()| 0)
        }
        XtraceCommand::Daemon { project_dir } => crate::daemon::run(project_dir).await.map(|()| 0),
        #[cfg(unix)]
        XtraceCommand::Attach { project_dir, pid, java_pack, json } => {
            crate::attach::run(project_dir, pid, java_pack, json).await.map(|()| 0)
        }
        XtraceCommand::Run {
            project_dir,
            java_agent,
            node_adapter,
            node_mode,
            observed_endpoint_policy,
            application_component,
            binding_key,
            command,
        } => {
            validate_safe_run_identity(application_component.as_deref(), binding_key.as_deref())?;
            if let Some(java_agent) = java_agent {
                crate::run::run(
                    project_dir,
                    java_agent,
                    observed_endpoint_policy,
                    application_component,
                    binding_key,
                    command,
                )
                .await
            } else if let (Some(node_adapter), Some(node_mode)) = (node_adapter, node_mode) {
                if observed_endpoint_policy.is_some()
                    || application_component.is_some()
                    || binding_key.is_some()
                {
                    return Err(CliError::InvalidArgument(
                        "Node capture does not yet support endpoint observation options"
                            .to_string(),
                    ));
                }
                crate::run::run_node(project_dir, node_adapter, node_mode, command).await
            } else {
                Err(CliError::InvalidArgument(
                    "run requires either --java-agent or --node-adapter with --node-mode"
                        .to_string(),
                ))
            }
        }
    }
}

fn validate_safe_run_identity(
    component: Option<&str>,
    binding: Option<&str>,
) -> Result<(), CliError> {
    fn valid(value: &str) -> bool {
        let bytes = value.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 64
            && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
            && bytes.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
    }
    if component
        .zip(binding)
        .is_some_and(|(component, binding)| !valid(component) || !valid(binding))
    {
        return Err(CliError::InvalidArgument(
            "application component and binding key must be safe IDs".to_string(),
        ));
    }
    Ok(())
}

fn recording<F>(command: RecordingCommand, env_reader: &F) -> Result<(), CliError>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    match command {
        RecordingCommand::List { project_dir, limit, after, unmatched, cursor } => {
            // Reject mixed cursor contracts before resolving the project or opening SQLite.
            if (unmatched && after.is_some()) || (!unmatched && cursor.is_some()) {
                return Err(endpoint_query_error(
                    "XTR-VALIDATION-ENDPOINT-QUERY",
                    "recording list cursor options are incompatible",
                    CorrelationId::new(),
                ));
            }
            let correlation_id = CorrelationId::new();
            let limit = parse_limit(limit.as_deref(), correlation_id)?;
            let mut stdout = std::io::stdout().lock();
            if unmatched {
                let (project_id, queries, correlation_id) =
                    open_observed_endpoint_queries(&project_dir, env_reader)?;
                let page = queries.list_unmatched_recordings(
                    ListUnmatchedRecordings { project_id, limit, cursor },
                    correlation_id,
                )?;
                write_success(&mut stdout, &page)?;
            } else {
                let after = after
                    .as_deref()
                    .map(|value| parse_recording_cursor(value, correlation_id))
                    .transpose()?;
                let (project_id, recording_queries, correlation_id) =
                    open_recording_queries(&project_dir, env_reader)?;
                let default_limit = xtrace_application::DEFAULT_RECORDING_LIST_LIMIT;
                let limit = limit.unwrap_or(default_limit);
                let page = recording_queries
                    .list(ListRecordings { project_id, limit, after }, correlation_id)?;
                write_success(&mut stdout, &page)?;
            }
            Ok(())
        }
        RecordingCommand::Show { project_dir, recording_id, limit, cursor } => {
            let (project_id, recording_queries, correlation_id) =
                open_recording_queries(&project_dir, env_reader)?;
            let detail = recording_queries
                .show(ShowRecording { project_id, recording_id, limit, cursor }, correlation_id)?;
            let mut stdout = std::io::stdout().lock();
            write_success(&mut stdout, &detail)?;
            Ok(())
        }
    }
}

fn endpoint<F>(command: EndpointCommand, env_reader: &F) -> Result<(), CliError>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let correlation_id = CorrelationId::new();
    let mut stdout = std::io::stdout().lock();
    match command {
        EndpointCommand::List { project_dir, limit, cursor } => {
            let limit = parse_limit(limit.as_deref(), correlation_id)?;
            let (project_id, queries, correlation_id) =
                open_observed_endpoint_queries(&project_dir, env_reader)?;
            let page = queries.list_observed_endpoints(
                ListObservedEndpoints { project_id, limit, cursor },
                correlation_id,
            )?;
            write_success(&mut stdout, &page)?;
        }
        EndpointCommand::Recordings { operation_id, project_dir, limit, cursor } => {
            let operation_id = parse_operation_id(&operation_id, correlation_id)?;
            let limit = parse_limit(limit.as_deref(), correlation_id)?;
            let (project_id, queries, correlation_id) =
                open_observed_endpoint_queries(&project_dir, env_reader)?;
            let page = queries.list_operation_recordings(
                ListOperationRecordings { project_id, operation_id, limit, cursor },
                correlation_id,
            )?;
            write_success(&mut stdout, &page)?;
        }
    }
    Ok(())
}

fn parse_limit(
    value: Option<&str>,
    correlation_id: CorrelationId,
) -> Result<Option<u32>, CliError> {
    value
        .map(|value| {
            value.parse::<u32>().map_err(|_| {
                endpoint_query_error(
                    "XTR-VALIDATION-ENDPOINT-QUERY",
                    "observed endpoint query limit is invalid",
                    correlation_id,
                )
            })
        })
        .transpose()
}

fn parse_recording_cursor(
    value: &str,
    correlation_id: CorrelationId,
) -> Result<RecordingId, CliError> {
    value.parse::<RecordingId>().map_err(|_| {
        endpoint_query_error(
            "XTR-VALIDATION-RECORDING-CURSOR",
            "recording list cursor is malformed",
            correlation_id,
        )
    })
}

fn parse_operation_id(value: &str, correlation_id: CorrelationId) -> Result<OperationId, CliError> {
    let operation_id = value.parse::<OperationId>().map_err(|_| {
        endpoint_query_error(
            "XTR-VALIDATION-ENDPOINT-QUERY",
            "observed endpoint query input is invalid",
            correlation_id,
        )
    })?;
    if operation_id.to_string() != value {
        return Err(endpoint_query_error(
            "XTR-VALIDATION-ENDPOINT-QUERY",
            "observed endpoint query input is invalid",
            correlation_id,
        ));
    }
    Ok(operation_id)
}

fn endpoint_query_error(code: &'static str, message: &'static str, id: CorrelationId) -> CliError {
    AppError::new(ErrorCode::new(code), ErrorCategory::Validation, message, RetryAdvice::None, id)
        .into()
}

pub(crate) fn open_recording_queries<F>(
    project_dir: &Path,
    env_reader: &F,
) -> Result<
    (
        xtrace_domain::ProjectId,
        RecordingQueryService<SqliteRecordingReader>,
        xtrace_domain::CorrelationId,
    ),
    CliError,
>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let (project_id, reader, correlation_id) = open_recording_reader(project_dir, env_reader)?;
    Ok((project_id, RecordingQueryService::new(reader), correlation_id))
}

fn open_observed_endpoint_queries<F>(
    project_dir: &Path,
    env_reader: &F,
) -> Result<
    (
        xtrace_domain::ProjectId,
        ObservedEndpointQueryService<SqliteRecordingReader>,
        xtrace_domain::CorrelationId,
    ),
    CliError,
>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let (project_id, reader, correlation_id) = open_recording_reader(project_dir, env_reader)?;
    Ok((project_id, ObservedEndpointQueryService::new(reader), correlation_id))
}

pub(crate) fn open_recording_reader<F>(
    project_dir: &Path,
    env_reader: &F,
) -> Result<(xtrace_domain::ProjectId, SqliteRecordingReader, xtrace_domain::CorrelationId), CliError>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let repo = resolve_repo(project_dir)?;
    let pointer = RepositoryPointer::read(&repo)?;
    let data_home = resolve_data_home(Some(&pointer), env_reader)?;
    let project_directory = UserDataPaths::project_dir_with_home(&data_home, pointer.project_id)?;
    let database_path = UserDataPaths::database_path_with_home(&data_home, pointer.project_id)?;
    let private_root = AdmittedPrivateRoot::open(&project_directory)
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    private_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
    private_root
        .validate_regular_file("metadata.sqlite3")
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    let context = RequestContext::new(env_user(), WallTime::now());
    let store = SqliteStore::open(
        &database_path,
        xtrace_store::OpenOptions::default()
            .with_must_exist(true)
            .with_read_only(true)
            .with_correlation_id(context.correlation_id),
    )
    .map_err(map_store_error)?;
    private_root
        .validate_regular_file("metadata.sqlite3")
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    private_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
    let repository = SqliteProjectRepository::new(&store);
    let idempotency = SqliteIdempotencyStore::new(&store);
    let app = Application::new(repository, idempotency, CURRENT_SCHEMA_VERSION, 1, 0);
    let canonical_repo_path = repo.to_string_lossy().into_owned();
    let project = match app
        .query(Query::GetProject(GetProject { canonical_repo_path }), &context)
        .map_err(CliError::from)?
    {
        QueryResult::Project(snapshot) => snapshot.project,
        QueryResult::StoreStatus(_) => {
            return Err(CliError::InvalidArgument("unexpected project query result".to_owned()));
        }
    };
    if project.id() != pointer.project_id {
        return Err(CliError::from(AppError::new(
            ErrorCode::new("XTR-PROJECT-POINTER-MISMATCH"),
            ErrorCategory::Corruption,
            "repository pointer does not match the registered project",
            RetryAdvice::None,
            context.correlation_id,
        )));
    }
    let reader = SqliteRecordingReader::new(store, project_directory).with_source_root(repo);
    Ok((project.id(), reader, context.correlation_id))
}

/// Resolves the user-data home directory for the supplied pointer
/// using the supplied environment reader.
///
/// Precedence:
///
/// 1. `XTRACE_DATA_HOME` when it points at an absolute path (the
///    caller-level override wins by design).
/// 2. The pointer's recorded `data_home` when the caller did not
///    set an override.
/// 3. The platform default via [`UserDataPaths::home_with`].
pub(crate) fn resolve_data_home<F>(
    pointer: Option<&RepositoryPointer>,
    env_reader: &F,
) -> Result<PathBuf, CliError>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    if let Some(value) = env_reader("XTRACE_DATA_HOME") {
        if value.is_absolute() {
            return Ok(value);
        }
    }
    if let Some(pointer) = pointer {
        if pointer.data_home.is_absolute() {
            return Ok(pointer.data_home.clone());
        }
    }
    UserDataPaths::home_with(env_reader)
}

fn init<F>(
    project_dir: PathBuf,
    display_name: String,
    idempotency_key: String,
    env_reader: &F,
) -> Result<(), CliError>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let repo = resolve_repo(&project_dir)?;
    let canonical = repo
        .to_str()
        .ok_or_else(|| CliError::InvalidArgument("repository path must be valid UTF-8".into()))?
        .to_string();
    if canonical.is_empty() || canonical.contains('\0') {
        return Err(CliError::InvalidArgument("repository path is invalid".into()));
    }
    if canonical.len() > crate::pointer_io::MAX_PATH_BYTES {
        return Err(CliError::InvalidArgument(
            "repository path exceeds its supported limit".into(),
        ));
    }
    let display_name = if display_name.trim().is_empty() {
        repo.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| canonical.clone())
    } else {
        display_name.trim().to_string()
    };
    let idempotency_key = if idempotency_key.trim().is_empty() {
        default_init_idempotency_key(&canonical)
    } else {
        idempotency_key.trim().to_string()
    };
    if display_name.is_empty() || display_name.len() > 128 {
        return Err(CliError::InvalidArgument("display name must contain 1 to 128 bytes".into()));
    }
    if idempotency_key.is_empty()
        || idempotency_key.len() > 128
        || idempotency_key.contains(['\0', '\n', '\r'])
    {
        return Err(CliError::InvalidArgument("idempotency key is invalid".into()));
    }
    let requested_at = WallTime::now();
    let ctx = RequestContext::new(env_user(), requested_at);
    let lock = crate::pointer_io::RepositoryInitLock::acquire(&repo)?;
    let existing_pointer = RepositoryPointer::read_locked(&lock)?;
    if existing_pointer.is_some()
        && env_reader("XTRACE_DATA_HOME").is_some_and(|override_home| !override_home.is_absolute())
    {
        return Err(CliError::StoreCorrupted(
            "configured data home must be absolute and match the repository pointer".into(),
        ));
    }
    let selected_home = resolve_data_home(existing_pointer.as_ref(), env_reader)?;
    let user_data_home = crate::paths::normalize_absolute_path(&selected_home)?;
    let fingerprint = xtrace_domain::RepositoryFingerprint::from_canonical_path(&canonical);
    if let Some(pointer) = existing_pointer.as_ref() {
        let pointer_home = crate::paths::normalize_absolute_path(&pointer.data_home)?;
        if pointer_home != user_data_home {
            return Err(CliError::StoreCorrupted(
                "configured data home does not match the repository pointer".into(),
            ));
        }
    }
    let pending_bytes = lock.read("init.pending", crate::pointer_io::PENDING_MAX_BYTES)?;
    let pending = pending_bytes.as_deref().map(crate::paths::PendingInit::parse).transpose()?;
    let selected_project_id = existing_pointer
        .as_ref()
        .map(|pointer| pointer.project_id)
        .or_else(|| pending.as_ref().map(crate::paths::PendingInit::project_id))
        .unwrap_or_else(xtrace_domain::ProjectId::new);
    let candidate = crate::paths::PendingInit::new(
        fingerprint.as_str().to_string(),
        selected_project_id,
        user_data_home.clone(),
        &display_name,
        &idempotency_key,
        &canonical,
    )?;
    let marker = match (&existing_pointer, pending) {
        (Some(pointer), Some(marker)) => {
            if marker.project_id() != pointer.project_id || marker.data_home() != user_data_home {
                return Err(CliError::StoreCorrupted(
                    "pending init identity conflicts with repository pointer".into(),
                ));
            }
            if !marker.matches_request(
                fingerprint.as_str(),
                &user_data_home,
                &display_name,
                &idempotency_key,
                &canonical,
            ) {
                return Err(CliError::StoreCorrupted(
                    "pending init input conflicts with repository state".into(),
                ));
            }
            marker
        }
        (Some(pointer), None) => crate::paths::PendingInit::new(
            fingerprint.as_str().to_string(),
            pointer.project_id,
            user_data_home.clone(),
            &display_name,
            &idempotency_key,
            &canonical,
        )?,
        (None, Some(marker)) => {
            let expected_home =
                crate::paths::normalize_absolute_path(&UserDataPaths::home_with(env_reader)?)?;
            if marker.data_home() != expected_home
                || !marker.matches_request(
                    fingerprint.as_str(),
                    &expected_home,
                    &display_name,
                    &idempotency_key,
                    &canonical,
                )
            {
                return Err(CliError::StoreCorrupted(
                    "pending init input or data home does not match this retry".into(),
                ));
            }
            marker
        }
        (None, None) => candidate,
    };
    let project_id =
        existing_pointer.as_ref().map_or_else(|| marker.project_id(), |pointer| pointer.project_id);
    let pointer =
        RepositoryPointer { schema_version: 1, project_id, data_home: user_data_home.clone() };
    let pointer_bytes = pointer.serialized()?;
    let publish_pending = existing_pointer.is_none() && pending_bytes.is_none();
    if publish_pending {
        let marker_bytes = marker.serialized()?;
        lock.publish("init.pending", &marker_bytes, crate::pointer_io::PENDING_MAX_BYTES)?;
    }
    lock.revalidate()?;

    let project_directory = UserDataPaths::project_dir_with_home(&user_data_home, project_id)?;
    let database_path = UserDataPaths::database_path_with_home(&user_data_home, project_id)?;
    let private_root = if existing_pointer.is_some() {
        AdmittedPrivateRoot::open(&project_directory)
            .map_err(|_| CliError::PrivateStorageUnavailable)?
    } else {
        AdmittedPrivateRoot::open_or_create(&project_directory)
            .map_err(|_| CliError::PrivateStorageUnavailable)?
    };
    private_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
    let database = if existing_pointer.is_some() {
        private_root.open_regular_file("metadata.sqlite3")
    } else {
        private_root.open_or_create_private_file("metadata.sqlite3")
    }
    .map_err(|_| CliError::PrivateStorageUnavailable)?;
    drop(database);
    private_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
    let mut options = xtrace_store::OpenOptions::default().with_correlation_id(ctx.correlation_id);
    if existing_pointer.is_some() {
        options = options.with_must_exist(true);
    }
    let store = SqliteStore::open(&database_path, options).map_err(map_store_error)?;
    private_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
    private_root
        .validate_regular_file("metadata.sqlite3")
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    let repository = SqliteProjectRepository::new(&store);
    let idempotency = SqliteIdempotencyStore::new(&store);
    let app = Application::new(repository, idempotency, CURRENT_SCHEMA_VERSION, 1, 0);
    let receipt = app
        .execute(
            Command::InitializeProject(InitializeProject {
                canonical_repo_path: canonical,
                display_name,
                idempotency_key,
                project_id,
            }),
            &ctx,
        )
        .map_err(CliError::from)?;

    lock.revalidate()?;
    pointer.write_locked(&lock, &pointer_bytes)?;
    if pending_bytes.is_some() || publish_pending {
        let pending_file = lock.open_owned("init.pending")?;
        lock.remove_owned("init.pending", &pending_file)?;
    }

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let document = InitDocument::from_receipt(&receipt, &pointer, &repo, &database_path);
    write_success(&mut handle, &document)?;
    Ok(())
}

fn default_init_idempotency_key(canonical_repo_path: &str) -> String {
    let legacy = format!("xtrace-init-{canonical_repo_path}");
    if legacy.len() <= 128 && !legacy.contains(['\0', '\n', '\r']) {
        legacy
    } else {
        format!("xtrace-init-v1-{}", blake3::hash(canonical_repo_path.as_bytes()).to_hex())
    }
}

fn open<F>(project_dir: PathBuf, idempotency_key: String, env_reader: &F) -> Result<(), CliError>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let repo = resolve_repo(&project_dir)?;
    let pointer = RepositoryPointer::read(&repo)?;
    let data_home = resolve_data_home(Some(&pointer), env_reader)?;
    let project_directory = UserDataPaths::project_dir_with_home(&data_home, pointer.project_id)?;
    let database_path = UserDataPaths::database_path_with_home(&data_home, pointer.project_id)?;
    let private_root = AdmittedPrivateRoot::open(&project_directory)
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    private_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
    let requested_at = WallTime::now();
    let ctx = RequestContext::new(env_user(), requested_at);

    let store = SqliteStore::open(
        &database_path,
        xtrace_store::OpenOptions::default()
            .with_must_exist(true)
            .with_correlation_id(ctx.correlation_id),
    )
    .map_err(map_store_error)?;
    private_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
    let repository = SqliteProjectRepository::new(&store);
    let idempotency = SqliteIdempotencyStore::new(&store);
    let app = Application::new(repository, idempotency, CURRENT_SCHEMA_VERSION, 1, 0);

    let canonical = repo.display().to_string();
    let resolved_idempotency_key = if idempotency_key.trim().is_empty() {
        format!("xtrace-open-{canonical}")
    } else {
        idempotency_key
    };
    let receipt = app
        .execute(
            Command::OpenProject(OpenProject {
                canonical_repo_path: canonical,
                idempotency_key: resolved_idempotency_key,
            }),
            &ctx,
        )
        .map_err(CliError::from)?;

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let document = OpenDocument::from_receipt(&receipt, &repo, &database_path);
    write_success(&mut handle, &document)?;
    Ok(())
}

fn status<F>(project_dir: PathBuf, env_reader: &F) -> Result<(), CliError>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    let repo = resolve_repo(&project_dir)?;
    let requested_at = WallTime::now();
    let ctx = RequestContext::new(env_user(), requested_at);

    // Status on an uninitialized repository reports the empty state
    // without opening or creating any database file. The check is
    // purely about the pointer file; the database is never touched
    // when the pointer is absent.
    let document = match RepositoryPointer::read(&repo) {
        Ok(pointer) => {
            let data_home = resolve_data_home(Some(&pointer), env_reader)?;
            let project_directory =
                UserDataPaths::project_dir_with_home(&data_home, pointer.project_id)?;
            let database_path =
                UserDataPaths::database_path_with_home(&data_home, pointer.project_id)?;
            let private_root = AdmittedPrivateRoot::open(&project_directory)
                .map_err(|_| CliError::PrivateStorageUnavailable)?;
            private_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
            let store = SqliteStore::open(
                &database_path,
                xtrace_store::OpenOptions::default()
                    .with_must_exist(true)
                    .with_correlation_id(ctx.correlation_id),
            )
            .map_err(map_store_error)?;
            private_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
            let repository = SqliteProjectRepository::new(&store);
            let idempotency = SqliteIdempotencyStore::new(&store);
            let app = Application::new(repository, idempotency, CURRENT_SCHEMA_VERSION, 1, 0);
            let result = app.query(Query::GetStoreStatus(GetStoreStatus), &ctx)?;
            match result {
                xtrace_application::QueryResult::StoreStatus(report) => {
                    StatusDocument::from_report(
                        report,
                        store.bootstrap().schema_version,
                        &repo,
                        &database_path,
                    )
                }
                xtrace_application::QueryResult::Project(_) => {
                    unreachable!("GetStoreStatus must produce a StoreStatus variant")
                }
            }
        }
        Err(CliError::ProjectDirectoryMissing(_)) => empty_status_document(&repo),
        Err(err) => return Err(err),
    };

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    write_success(&mut handle, &document)?;
    Ok(())
}

pub(crate) fn resolve_repo(project_dir: &Path) -> Result<PathBuf, CliError> {
    if !project_dir.exists() {
        return Err(CliError::ProjectDirectoryMissing(project_dir.display().to_string()));
    }
    if !project_dir.is_dir() {
        return Err(CliError::InvalidArgument(format!(
            "project path is not a directory: {}",
            project_dir.display()
        )));
    }
    project_dir.canonicalize().map_err(|err| CliError::StoreUnavailable(err.to_string()))
}

fn empty_status_document(repo: &Path) -> StatusDocument {
    let canonical = repo.display().to_string();
    let capabilities = xtrace_application::CapabilityReport {
        store_schema_version: CURRENT_SCHEMA_VERSION,
        protocol_major: 1,
        protocol_minor: 0,
        capture_supported: false,
        replay_supported: false,
    };
    StatusDocument {
        kind: "store_status",
        initialized: false,
        project_dir: canonical,
        database_path: String::new(),
        store_schema_version: 0,
        capabilities,
        projects: Vec::new(),
    }
}

/// Best-effort "who ran the command" placeholder. The CLI does not
/// authenticate; future slices replace this with the resolved
/// principal from the daemon.
fn env_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Maps [`xtrace_store::StoreError`] categories into [`CliError`].
pub(crate) fn map_store_error(err: xtrace_store::StoreError) -> CliError {
    match err.kind() {
        StoreErrorKind::Corruption | StoreErrorKind::SchemaIncompatible => {
            CliError::StoreCorrupted(err.message().to_string())
        }
        StoreErrorKind::SchemaNewer => CliError::StoreSchemaNewer(err.message().to_string()),
        StoreErrorKind::SchemaOlder => CliError::StoreSchemaOlder(err.message().to_string()),
        StoreErrorKind::Transport => CliError::StoreUnavailable(err.message().to_string()),
        StoreErrorKind::Permission => CliError::PrivateStorageUnavailable,
        StoreErrorKind::Busy => CliError::StoreUnavailable(err.message().to_string()),
        StoreErrorKind::Validation => CliError::StoreUnavailable(err.message().to_string()),
        _ => CliError::StoreUnavailable(err.message().to_string()),
    }
}

/// Stable JSON shape of an `init` receipt.
#[derive(Debug, Serialize)]
pub struct InitDocument {
    pub kind: &'static str,
    pub project_id: String,
    pub fingerprint: String,
    pub idempotency_key: String,
    pub project_dir: String,
    pub database_path: String,
    pub data_home: String,
    pub schema_version: u32,
}

impl InitDocument {
    fn from_receipt(
        receipt: &xtrace_application::CommandReceipt,
        pointer: &RepositoryPointer,
        repo: &Path,
        database_path: &Path,
    ) -> Self {
        match receipt {
            xtrace_application::CommandReceipt::ProjectInitialized {
                project_id,
                fingerprint,
                idempotency_key,
            } => Self {
                kind: "project_initialized",
                project_id: project_id.to_string(),
                fingerprint: fingerprint.as_str().to_string(),
                idempotency_key: idempotency_key.clone(),
                project_dir: repo.display().to_string(),
                database_path: database_path.display().to_string(),
                data_home: pointer.data_home.display().to_string(),
                schema_version: CURRENT_SCHEMA_VERSION,
            },
            _ => unreachable!("InitializeProject must yield a ProjectInitialized receipt"),
        }
    }
}

/// Stable JSON shape of an `open` receipt.
#[derive(Debug, Serialize)]
pub struct OpenDocument {
    pub kind: &'static str,
    pub project_id: String,
    pub idempotency_key: String,
    pub project_dir: String,
    pub database_path: String,
}

impl OpenDocument {
    fn from_receipt(
        receipt: &xtrace_application::CommandReceipt,
        repo: &Path,
        database_path: &Path,
    ) -> Self {
        match receipt {
            xtrace_application::CommandReceipt::ProjectOpened { project_id, idempotency_key } => {
                Self {
                    kind: "project_opened",
                    project_id: project_id.to_string(),
                    idempotency_key: idempotency_key.clone(),
                    project_dir: repo.display().to_string(),
                    database_path: database_path.display().to_string(),
                }
            }
            _ => unreachable!("OpenProject must yield a ProjectOpened receipt"),
        }
    }
}

/// Stable JSON shape of a `status` report.
#[derive(Debug, Serialize)]
pub struct StatusDocument {
    pub kind: &'static str,
    /// `false` when the repository pointer is absent. The CLI emits
    /// an empty report in that case without touching the database.
    pub initialized: bool,
    pub project_dir: String,
    pub database_path: String,
    pub store_schema_version: u32,
    pub capabilities: xtrace_application::CapabilityReport,
    pub projects: Vec<xtrace_application::ProjectStatus>,
}

impl StatusDocument {
    fn from_report(
        report: xtrace_application::StoreStatusReport,
        schema_version: u32,
        repo: &Path,
        database_path: &Path,
    ) -> Self {
        Self {
            kind: "store_status",
            initialized: true,
            project_dir: repo.display().to_string(),
            database_path: database_path.display().to_string(),
            store_schema_version: schema_version,
            capabilities: report.capabilities,
            projects: report.projects,
        }
    }
}

#[cfg(test)]
// Tests assert on fallible fixture data and exercise fallible
// branches that library code deliberately avoids. The workspace
// denies `unsafe_code` and the `panic` lint, so the test module
// allows them locally; `panic` only appears in invariant
// assertions that should fail the test outright when violated.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on fallible fixture data and explicit invariants"
)]
mod tests {
    use super::*;
    use crate::paths::USER_DATA_HOME_ENV;
    use std::collections::HashMap;
    use xtrace_domain::ProjectId;

    fn dto_fixture_pointer() -> (RepositoryPointer, PathBuf, PathBuf) {
        let repo = PathBuf::from("/canonical/checkout/repository");
        let data_home = PathBuf::from("/owner-private/xtrace-data");
        let pointer = RepositoryPointer {
            schema_version: 1,
            project_id: ProjectId::new(),
            data_home: data_home.clone(),
        };
        (pointer, repo, data_home)
    }

    #[test]
    fn init_document_reports_canonical_repository_and_separate_data_home() {
        let (pointer, repo, data_home) = dto_fixture_pointer();
        let receipt = xtrace_application::CommandReceipt::ProjectInitialized {
            project_id: pointer.project_id,
            fingerprint: xtrace_domain::RepositoryFingerprint::from_canonical_path(
                repo.to_str().expect("UTF-8 fixture repo"),
            ),
            idempotency_key: "owner-local-key".into(),
        };
        let database_path = data_home.join("projects").join("metadata.sqlite3");
        let document = InitDocument::from_receipt(&receipt, &pointer, &repo, &database_path);
        assert_eq!(document.project_dir, repo.display().to_string());
        assert_eq!(document.data_home, data_home.display().to_string());
        assert_eq!(document.idempotency_key, "owner-local-key");
    }

    #[test]
    fn open_document_reports_canonical_repository() {
        let (pointer, repo, data_home) = dto_fixture_pointer();
        let receipt = xtrace_application::CommandReceipt::ProjectOpened {
            project_id: pointer.project_id,
            idempotency_key: "owner-local-open-key".into(),
        };
        let database_path = data_home.join("projects").join("metadata.sqlite3");
        let document = OpenDocument::from_receipt(&receipt, &repo, &database_path);
        assert_eq!(document.project_dir, repo.display().to_string());
        assert_eq!(document.database_path, database_path.display().to_string());
    }

    #[test]
    fn initialized_status_reports_canonical_repository() {
        let (_pointer, repo, data_home) = dto_fixture_pointer();
        let report = xtrace_application::StoreStatusReport {
            capabilities: xtrace_application::CapabilityReport {
                store_schema_version: CURRENT_SCHEMA_VERSION,
                protocol_major: 1,
                protocol_minor: 0,
                capture_supported: false,
                replay_supported: false,
            },
            current_schema_version: CURRENT_SCHEMA_VERSION,
            target_schema_version: CURRENT_SCHEMA_VERSION,
            projects: Vec::new(),
            diagnostics: std::collections::BTreeMap::new(),
        };
        let database_path = data_home.join("projects").join("metadata.sqlite3");
        let document =
            StatusDocument::from_report(report, CURRENT_SCHEMA_VERSION, &repo, &database_path);
        assert!(document.initialized);
        assert_eq!(document.project_dir, repo.display().to_string());
        assert_eq!(document.database_path, database_path.display().to_string());
    }

    #[test]
    fn absent_pointer_status_keeps_the_canonical_repository_path() {
        let repo = Path::new("/canonical/checkout/uninitialized-repository");
        let document = empty_status_document(repo);
        assert!(!document.initialized);
        assert_eq!(document.project_dir, repo.display().to_string());
    }

    #[test]
    fn default_init_key_is_bounded_and_path_specific() {
        let long_path = format!("/{}", "a".repeat(crate::pointer_io::MAX_PATH_BYTES - 1));
        let key = default_init_idempotency_key(&long_path);
        assert!(key.len() <= 128);
        assert_eq!(key, default_init_idempotency_key(&long_path));
        assert_ne!(key, default_init_idempotency_key("/different"));
        assert_eq!(
            default_init_idempotency_key("/short/repository"),
            "xtrace-init-/short/repository"
        );
        assert!(key.starts_with("xtrace-init-v1-"));
    }

    #[test]
    fn init_replays_historical_implicit_key_receipt_without_rewriting_it() {
        use xtrace_application::IdempotencyStore as _;

        let repo = legacy_key_repo_dir();
        let home = tempdir("legacy-default-key-home");
        let env_reader = move |name: &str| (name == USER_DATA_HOME_ENV).then(|| home.clone());
        let canonical = resolve_repo(&repo).expect("canonical repository");
        let canonical = canonical.to_str().expect("UTF-8 repository");
        let legacy_key = require_parent_legacy_key(canonical);
        init(repo.clone(), "Legacy".into(), String::new(), &env_reader)
            .expect("initial project and receipt");
        let pointer = RepositoryPointer::read(&repo).expect("pointer");
        let database_path =
            UserDataPaths::database_path_with_home(&pointer.data_home, pointer.project_id)
                .expect("database path");
        let store = SqliteStore::open(&database_path, xtrace_store::OpenOptions::default())
            .expect("open initialized store");
        let idempotency = SqliteIdempotencyStore::new(&store);
        let original = idempotency
            .lookup_receipt("initialize_project", &legacy_key)
            .expect("lookup legacy receipt")
            .expect("legacy receipt exists");
        drop(store);

        init(repo.clone(), "Legacy".into(), String::new(), &env_reader)
            .expect("exact historical default-key retry");
        let store = SqliteStore::open(&database_path, xtrace_store::OpenOptions::default())
            .expect("reopen initialized store");
        let idempotency = SqliteIdempotencyStore::new(&store);
        let replayed = idempotency
            .lookup_receipt("initialize_project", &legacy_key)
            .expect("lookup replayed receipt")
            .expect("replayed receipt exists");
        assert_eq!(replayed.receipt_json, original.receipt_json);
        assert_eq!(replayed.input_digest, original.input_digest);
        assert_eq!(replayed.project_id, original.project_id);
        assert_eq!(replayed.idempotency_key, original.idempotency_key);
        assert_eq!(
            std::fs::read_dir(pointer.data_home.join("projects"))
                .expect("project directories")
                .count(),
            1
        );
    }

    #[test]
    fn init_reuses_the_durable_marker_after_private_database_root_failure() {
        let repo = tempdir("init-recovery-repo");
        let data_home = tempdir("init-recovery-home").join("blocked-home");
        std::fs::write(&data_home, b"injected database-root creation failure")
            .expect("block private root creation");
        let configured_home = data_home.clone();
        let env_reader =
            move |name: &str| (name == USER_DATA_HOME_ENV).then(|| configured_home.clone());

        let first = init(repo.clone(), "Recovery".into(), String::new(), &env_reader);
        assert!(first.is_err());
        let marker_bytes = crate::pointer_io::read_unlocked(
            &repo,
            "init.pending",
            crate::pointer_io::PENDING_MAX_BYTES,
        )
        .expect("read pending marker")
        .expect("marker survives database-root failure");
        let original_project_id = crate::paths::PendingInit::parse(&marker_bytes)
            .expect("valid pending marker")
            .project_id();

        std::fs::remove_file(&data_home).expect("remove injected blocker");
        std::fs::create_dir(&data_home).expect("allow private root creation");
        init(repo.clone(), "Recovery".into(), String::new(), &env_reader)
            .expect("retry init with same marker");
        let pointer = crate::paths::RepositoryPointer::read(&repo).expect("published pointer");
        assert_eq!(pointer.project_id, original_project_id);
        assert!(
            crate::pointer_io::read_unlocked(
                &repo,
                "init.pending",
                crate::pointer_io::PENDING_MAX_BYTES,
            )
            .expect("check marker cleanup")
            .is_none()
        );
    }

    #[test]
    fn safe_run_identity_uses_ascii_allowlist_and_never_echoes_input() {
        assert!(validate_safe_run_identity(Some("spring-fixture"), Some("default")).is_ok());
        assert!(validate_safe_run_identity(Some("A_private"), Some("default")).is_err());
        assert!(
            validate_safe_run_identity(Some("spring-fixture\nsecret"), Some("default")).is_err()
        );
        assert!(validate_safe_run_identity(Some(&"a".repeat(65)), Some("default")).is_err());
    }

    fn tempdir(label: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        // macOS clocks tick in microseconds: add a process-wide sequence so parallel tests never
        // collide on the directory name.
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let scratch = PathBuf::from(
            std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
                .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required"),
        );
        let root = AdmittedPrivateRoot::open(&scratch).expect("admitted private test scratch");
        root.create_private_child(&format!(
            "xtrace-cli-commands-{label}-{}-{sequence}-{nanos}",
            std::process::id()
        ))
        .expect("private CLI test directory")
        .path()
        .to_path_buf()
    }

    /// Maps a variable name to its configured value. Used to inject
    /// environment state into the command resolver without mutating
    /// the process-wide environment.
    fn reader(values: HashMap<&'static str, PathBuf>) -> impl Fn(&str) -> Option<PathBuf> {
        move |var: &str| values.get(var).cloned()
    }

    fn reader_with_none() -> impl Fn(&str) -> Option<PathBuf> {
        reader(HashMap::new())
    }

    fn legacy_pending_marker(
        repository_fingerprint: &str,
        project_id: xtrace_domain::ProjectId,
        data_home: &Path,
        display_name: &str,
        idempotency_key: &str,
        canonical_repo_path: &str,
    ) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct LegacyPending<'a> {
            schema_version: u32,
            repository_fingerprint: &'a str,
            project_id: xtrace_domain::ProjectId,
            data_home: &'a Path,
            display_name_digest: String,
            idempotency_key_digest: String,
            canonical_input_digest: String,
        }
        fn digest(value: &str) -> String {
            format!("b3:{}", blake3::hash(value.as_bytes()).to_hex())
        }
        toml::to_string_pretty(&LegacyPending {
            schema_version: 1,
            repository_fingerprint,
            project_id,
            data_home,
            display_name_digest: digest(display_name),
            idempotency_key_digest: digest(idempotency_key),
            canonical_input_digest: digest(&format!(
                "{canonical_repo_path}\n{display_name}\n{idempotency_key}"
            )),
        })
        .expect("historical v1 marker")
        .into_bytes()
    }

    fn legacy_key_repo_dir() -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        // Short on purpose (the path must stay under the socket-length bound): pid and a
        // process-wide sequence in hex keep parallel callers distinct on microsecond clocks.
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after UNIX epoch")
            .as_nanos();
        let scratch = PathBuf::from(
            std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
                .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required"),
        );
        let root = AdmittedPrivateRoot::open(&scratch).expect("admitted private test scratch");
        root.create_private_child(&format!(
            "r{:x}{sequence:x}{:x}",
            std::process::id(),
            nanos / 1000
        ))
        .expect("short legacy-key repository fixture under admitted scratch")
        .path()
        .to_path_buf()
    }

    fn require_parent_legacy_key(canonical_repo_path: &str) -> String {
        let key = format!("xtrace-init-{canonical_repo_path}");
        assert!(
            canonical_repo_path.len() <= 116,
            "legacy-key fixture repository path must be <=116 bytes; shorten XTRACE_TEST_PRIVATE_SCRATCH"
        );
        assert!(
            key.len() <= 128 && !key.contains(['\0', '\n', '\r']),
            "historical implicit key must pass the parent's exact 128-byte/control admission; shorten XTRACE_TEST_PRIVATE_SCRATCH"
        );
        assert_eq!(
            default_init_idempotency_key(canonical_repo_path),
            key,
            "fixture must exercise the historical implicit key, not the bounded fallback"
        );
        key
    }

    fn publish_pending_marker(repo: &Path, bytes: &[u8]) {
        let lock = crate::pointer_io::RepositoryInitLock::acquire(repo).expect("init lock");
        lock.publish("init.pending", bytes, crate::pointer_io::PENDING_MAX_BYTES)
            .expect("publish fixture marker");
    }

    #[test]
    fn v1_pending_marker_recovers_same_identity_before_database_commit() {
        let repo = legacy_key_repo_dir();
        let blocked_home = tempdir("v1-pending-precommit-home").join("blocked-home");
        std::fs::write(&blocked_home, b"injected private-root blocker").expect("block home");
        let configured_home = blocked_home.clone();
        let env_reader =
            move |name: &str| (name == USER_DATA_HOME_ENV).then(|| configured_home.clone());
        let canonical = resolve_repo(&repo).expect("canonical repo");
        let canonical = canonical.to_str().expect("UTF-8 repo");
        let fingerprint = xtrace_domain::RepositoryFingerprint::from_canonical_path(canonical);
        let display_name = "V1 recovery";
        let key = require_parent_legacy_key(canonical);
        let project_id = xtrace_domain::ProjectId::new();
        let original_marker = legacy_pending_marker(
            fingerprint.as_str(),
            project_id,
            &blocked_home,
            display_name,
            &key,
            canonical,
        );
        publish_pending_marker(&repo, &original_marker);

        assert!(init(repo.clone(), display_name.into(), String::new(), &env_reader).is_err());
        let after_failure = crate::pointer_io::read_unlocked(
            &repo,
            "init.pending",
            crate::pointer_io::PENDING_MAX_BYTES,
        )
        .expect("read preserved marker")
        .expect("marker remains");
        assert_eq!(after_failure, original_marker);
        assert!(RepositoryPointer::read(&repo).is_err());

        std::fs::remove_file(&blocked_home).expect("remove blocker");
        std::fs::create_dir(&blocked_home).expect("allow private root");
        init(repo.clone(), display_name.into(), String::new(), &env_reader)
            .expect("retry historical marker");
        let pointer = RepositoryPointer::read(&repo).expect("published pointer");
        assert_eq!(pointer.project_id, project_id);
        assert!(
            crate::pointer_io::read_unlocked(
                &repo,
                "init.pending",
                crate::pointer_io::PENDING_MAX_BYTES,
            )
            .expect("check marker cleanup")
            .is_none()
        );
        assert_eq!(
            std::fs::read_dir(blocked_home.join("projects")).expect("project directories").count(),
            1
        );
    }

    #[test]
    fn v1_pending_marker_replays_committed_receipt_without_duplicate_project() {
        use xtrace_application::IdempotencyStore as _;

        let repo = legacy_key_repo_dir();
        let home = tempdir("v1-pending-postcommit-home");
        let configured_home = home.clone();
        let env_reader =
            move |name: &str| (name == USER_DATA_HOME_ENV).then(|| configured_home.clone());
        let canonical = resolve_repo(&repo).expect("canonical repo");
        let canonical = canonical.to_str().expect("UTF-8 repo");
        let key = require_parent_legacy_key(canonical);
        let display_name = "V1 committed";
        init(repo.clone(), display_name.into(), String::new(), &env_reader)
            .expect("commit initial project and receipt");
        let original_pointer = RepositoryPointer::read(&repo).expect("initial pointer");
        let database_path = UserDataPaths::database_path_with_home(
            &original_pointer.data_home,
            original_pointer.project_id,
        )
        .expect("database path");
        let store = SqliteStore::open(&database_path, xtrace_store::OpenOptions::default())
            .expect("open store");
        let idempotency = SqliteIdempotencyStore::new(&store);
        let original_receipt = idempotency
            .lookup_receipt("initialize_project", &key)
            .expect("lookup committed receipt")
            .expect("receipt exists");
        drop(store);

        let pointer_path = repo.join(".xtrace").join("config.toml");
        std::fs::remove_file(pointer_path).expect("simulate crash before pointer publish");
        let fingerprint = xtrace_domain::RepositoryFingerprint::from_canonical_path(canonical);
        let marker = legacy_pending_marker(
            fingerprint.as_str(),
            original_pointer.project_id,
            &original_pointer.data_home,
            display_name,
            &key,
            canonical,
        );
        publish_pending_marker(&repo, &marker);

        init(repo.clone(), display_name.into(), String::new(), &env_reader)
            .expect("v1 post-commit exact receipt retry");
        let pointer = RepositoryPointer::read(&repo).expect("recovered pointer");
        assert_eq!(pointer.project_id, original_pointer.project_id);
        let store = SqliteStore::open(&database_path, xtrace_store::OpenOptions::default())
            .expect("reopen recovered store");
        let idempotency = SqliteIdempotencyStore::new(&store);
        let replayed_receipt = idempotency
            .lookup_receipt("initialize_project", &key)
            .expect("lookup replayed receipt")
            .expect("replayed receipt exists");
        assert_eq!(replayed_receipt.receipt_json, original_receipt.receipt_json);
        assert_eq!(replayed_receipt.input_digest, original_receipt.input_digest);
        assert_eq!(
            std::fs::read_dir(home.join("projects")).expect("project directories").count(),
            1
        );
    }

    #[test]
    fn resolve_data_home_prefers_explicit_override_over_pointer() {
        let a = tempdir("a");
        let b = tempdir("b");
        let pointer = RepositoryPointer {
            schema_version: 1,
            project_id: ProjectId::new(),
            data_home: a.clone(),
        };
        let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
        values.insert("XTRACE_DATA_HOME", b.clone());
        let resolved = resolve_data_home(Some(&pointer), &reader(values)).expect("resolve");
        assert_eq!(resolved, b);
    }

    #[test]
    fn resolve_data_home_uses_pointer_when_no_explicit_override() {
        let a = tempdir("pointer");
        let pointer = RepositoryPointer {
            schema_version: 1,
            project_id: ProjectId::new(),
            data_home: a.clone(),
        };
        let resolved = resolve_data_home(Some(&pointer), &reader_with_none()).expect("resolve");
        assert_eq!(resolved, a);
    }

    #[test]
    fn resolve_data_home_uses_platform_default_when_neither_override_nor_pointer() {
        // No `XTRACE_DATA_HOME`, no pointer. The platform default
        // (via `HOME` on macOS/Linux, `APPDATA` on Windows) must
        // resolve to an absolute path.
        let repo_dir = tempdir("platform-default");
        let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
        values.insert("HOME", repo_dir.clone());
        let resolved = resolve_data_home(None, &reader(values)).expect("resolve");
        assert!(resolved.is_absolute());
        // On macOS the default is `$HOME/Library/Application Support/xtrace`,
        // on Linux it is `${HOME}/.local/share/xtrace`, on Windows
        // `${APPDATA}/xtrace`. In every case the path must begin
        // with the supplied HOME when HOME is the source.
        assert!(
            resolved.starts_with(&repo_dir),
            "platform default must start with HOME, got {resolved:?}"
        );
    }

    #[test]
    fn open_status_fail_without_mutating_when_pointer_db_missing() {
        let repo_dir = tempdir("open-status");
        std::fs::create_dir_all(&repo_dir).expect("repo");
        let home = tempdir("home");
        let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
        values.insert("XTRACE_DATA_HOME", home.clone());
        values.insert("HOME", repo_dir.clone());
        let env_reader = reader(values);
        let pointer = RepositoryPointer {
            schema_version: 1,
            project_id: ProjectId::new(),
            data_home: home.clone(),
        };
        pointer.write(&repo_dir).expect("write pointer");
        // `open` must refuse a missing database without creating
        // either the user-data directory or the SQLite file.
        let err = open(repo_dir.clone(), String::new(), &env_reader).unwrap_err();
        assert!(
            matches!(err, CliError::PrivateStorageUnavailable),
            "open must fail without mutating: {err:?}"
        );
        assert!(!home.join("projects").exists(), "user-data directory must not be created");
        // `status` follows the same discipline.
        let err = status(repo_dir.clone(), &env_reader).unwrap_err();
        assert!(
            matches!(err, CliError::PrivateStorageUnavailable),
            "status must fail without mutating: {err:?}"
        );
        assert!(!home.join("projects").exists(), "user-data directory must not be created");
    }

    #[test]
    fn uninit_status_creates_neither_user_data_directory_nor_pointer() {
        let repo_dir = tempdir("uninit");
        std::fs::create_dir_all(&repo_dir).expect("repo");
        let home = tempdir("home");
        let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
        values.insert("XTRACE_DATA_HOME", home.clone());
        values.insert("HOME", repo_dir.clone());
        let env_reader = reader(values);
        // No pointer is present and `status` must produce an empty
        // document without creating either the user-data directory or
        // the repository pointer.
        status(repo_dir.clone(), &env_reader).expect("status on uninit must succeed");
        assert!(!home.join("projects").exists(), "user-data directory must not be created");
        assert!(!repo_dir.join(".xtrace").exists(), "repository pointer must not be created");
    }

    #[test]
    fn init_then_open_with_pointer_then_status_round_trips_under_changing_env() {
        let repo_dir = tempdir("roundtrip");
        std::fs::create_dir_all(&repo_dir).expect("repo");
        let a = tempdir("a");
        let b = tempdir("b");
        {
            let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
            values.insert("XTRACE_DATA_HOME", a.clone());
            values.insert("HOME", repo_dir.clone());
            init(repo_dir.clone(), "Example".to_string(), String::new(), &reader(values))
                .expect("init under A");
        }
        // With the explicit override set to B, every command looks
        // under B and refuses the absent database without mutating
        // either home.
        {
            let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
            values.insert("XTRACE_DATA_HOME", b.clone());
            values.insert("HOME", repo_dir.clone());
            let env_reader = reader(values);
            let open_err = open(repo_dir.clone(), String::new(), &env_reader).unwrap_err();
            assert!(matches!(open_err, CliError::PrivateStorageUnavailable));
            let status_err = status(repo_dir.clone(), &env_reader).unwrap_err();
            assert!(matches!(status_err, CliError::PrivateStorageUnavailable));
        }
        // With the override cleared, the pointer-recorded A wins
        // and the open succeeds.
        {
            let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
            values.insert("HOME", repo_dir.clone());
            open(repo_dir.clone(), String::new(), &reader(values))
                .expect("open under unset env uses pointer A");
        }
        // Database directory lives under A only.
        let projects = a.join("projects");
        assert!(projects.exists(), "user-data directory under A");
        let b_projects = b.join("projects");
        assert!(!b_projects.exists(), "user-data directory must not be created under B");
    }

    #[test]
    fn explicit_override_takes_precedence_over_pointer_after_init() {
        let repo_dir = tempdir("override");
        std::fs::create_dir_all(&repo_dir).expect("repo");
        let a = tempdir("a");
        let b = tempdir("b");
        {
            let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
            values.insert("XTRACE_DATA_HOME", a.clone());
            values.insert("HOME", repo_dir.clone());
            init(repo_dir.clone(), "Example".to_string(), String::new(), &reader(values))
                .expect("init under A");
        }
        // `open` with the explicit override set to an absolute path
        // must look under B and fail without creating anything there
        // because the database under B is absent.
        {
            let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
            values.insert("XTRACE_DATA_HOME", b.clone());
            values.insert("HOME", repo_dir.clone());
            let env_reader = reader(values);
            let err = open(repo_dir.clone(), String::new(), &env_reader).unwrap_err();
            assert!(matches!(err, CliError::PrivateStorageUnavailable));
            assert!(!b.join("projects").exists(), "no mutation under B");
        }
        // With the override cleared, `open` falls back to the
        // pointer-recorded A and succeeds.
        {
            let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
            values.insert("HOME", repo_dir.clone());
            open(repo_dir.clone(), String::new(), &reader(values))
                .expect("open under unset env uses pointer A");
        }
    }

    #[test]
    fn same_input_replay_returns_original_initialize_receipt() {
        // This guards the documented `init` idempotency contract:
        // the same canonical input with the same idempotency key
        // returns the original receipt and never creates a second
        // project row or a second pointer.
        let repo_dir = tempdir("replay");
        std::fs::create_dir_all(&repo_dir).expect("repo");
        let home = tempdir("home");
        let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
        values.insert("XTRACE_DATA_HOME", home.clone());
        values.insert("HOME", repo_dir.clone());
        let env_reader = reader(values.clone());
        init(repo_dir.clone(), "Example".to_string(), String::new(), &env_reader)
            .expect("first init");
        init(repo_dir.clone(), "Example".to_string(), String::new(), &env_reader)
            .expect("second init is a replay");
        // Exactly one project directory exists under `home`.
        let project_dirs: Vec<_> = std::fs::read_dir(home.join("projects"))
            .expect("projects dir")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(project_dirs.len(), 1, "second init must not add a new project directory");
    }

    #[test]
    fn changed_input_replay_surfaces_xtr_command_409() {
        // The CLI integration smoke gate relies on this: a second
        // `init` with a different `display_name` reusing the
        // computed idempotency key must surface
        // `XTR-COMMAND-409` without mutating the project set.
        let repo_dir = tempdir("conflict");
        std::fs::create_dir_all(&repo_dir).expect("repo");
        let home = tempdir("home");
        let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
        values.insert("XTRACE_DATA_HOME", home.clone());
        values.insert("HOME", repo_dir.clone());
        let env_reader = reader(values.clone());
        init(repo_dir.clone(), "Example".to_string(), String::new(), &env_reader)
            .expect("first init");
        let err =
            init(repo_dir.clone(), "Renamed".to_string(), String::new(), &env_reader).unwrap_err();
        match err {
            CliError::App(app_error) => {
                assert_eq!(app_error.code.as_str(), "XTR-COMMAND-409");
                assert_eq!(app_error.category, xtrace_domain::ErrorCategory::Conflict);
            }
            other => panic!("expected XTR-COMMAND-409 conflict, got {other:?}"),
        }
        let project_dirs: Vec<_> = std::fs::read_dir(home.join("projects"))
            .expect("projects dir")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(project_dirs.len(), 1, "conflict must not create a second project directory");
    }

    #[test]
    fn init_fails_when_pointer_is_corrupt_and_does_not_overwrite_or_create_user_data() {
        // Regression test: a corrupt pointer file must surface as a
        // corruption error rather than being silently treated as
        // "no pointer" and overwritten by a fresh init. The user-data
        // directory must not be created on the failure path so a
        // retry starts from a clean slate.
        let repo_dir = tempdir("corrupt");
        std::fs::create_dir_all(&repo_dir).expect("repo");
        std::fs::create_dir_all(repo_dir.join(".xtrace")).expect("pointer dir");
        std::fs::write(repo_dir.join(".xtrace").join("config.toml"), "this-is-not-valid-toml = ")
            .expect("write corrupt pointer");
        let home = tempdir("home");
        let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
        values.insert("XTRACE_DATA_HOME", home.clone());
        values.insert("HOME", repo_dir.clone());
        let env_reader = reader(values);
        let err =
            init(repo_dir.clone(), "Example".to_string(), String::new(), &env_reader).unwrap_err();
        assert!(
            matches!(err, CliError::StoreCorrupted(_)),
            "corrupt pointer must surface as StoreCorrupted, got {err:?}"
        );
        // The corrupt pointer must remain untouched; the file system
        // check below proves we did not overwrite it.
        let pointer_text = std::fs::read_to_string(repo_dir.join(".xtrace").join("config.toml"))
            .expect("pointer still readable");
        assert_eq!(pointer_text, "this-is-not-valid-toml = ");
        // No user-data directory must be created on the failure path.
        assert!(!home.join("projects").exists(), "user-data must not be created on failure");
    }

    #[cfg(unix)]
    #[test]
    fn init_enforces_owner_only_permissions_before_sqlite_creates_the_database() {
        // Regression test for the permission ordering: the project
        // directory must be `0700` and the database file `0600` once
        // `init` returns. The test exercises a real CLI invocation
        // and inspects the on-disk modes directly.
        use std::os::unix::fs::PermissionsExt as _;
        let repo_dir = tempdir("perms");
        std::fs::create_dir_all(&repo_dir).expect("repo");
        let home = tempdir("perms-home");
        let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
        values.insert("XTRACE_DATA_HOME", home.clone());
        values.insert("HOME", repo_dir.clone());
        let env_reader = reader(values);
        init(repo_dir.clone(), "Example".to_string(), String::new(), &env_reader).expect("init");
        let projects = home.join("projects");
        let project_dir = std::fs::read_dir(&projects)
            .expect("projects dir")
            .filter_map(Result::ok)
            .next()
            .expect("exactly one project directory");
        let dir_mode =
            std::fs::metadata(project_dir.path()).expect("dir metadata").permissions().mode()
                & 0o777;
        let db_mode = std::fs::metadata(project_dir.path().join("metadata.sqlite3"))
            .expect("db metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "project directory must be owner-only");
        assert_eq!(db_mode, 0o600, "database file must be owner-only");
    }

    #[cfg(unix)]
    #[test]
    fn oversized_display_name_is_rejected_before_any_storage_is_created() {
        // Recoverable initialization validates the display name in the CLI before any
        // project directory, database, or pointer exists, so an invalid fresh init leaves
        // no storage behind. (Owner-only modes of a successful fresh init are asserted by
        // the preceding mode test.)
        let repo_dir = tempdir("fresh-fail");
        std::fs::create_dir_all(&repo_dir).expect("repo");
        let home = tempdir("fresh-fail-home");
        let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
        values.insert("XTRACE_DATA_HOME", home.clone());
        values.insert("HOME", repo_dir.clone());
        let env_reader = reader(values);
        let oversized = "x".repeat(129);
        let err = init(repo_dir.clone(), oversized, String::new(), &env_reader).unwrap_err();
        assert!(
            matches!(err, CliError::InvalidArgument(_)),
            "oversized display name must be rejected as an invalid argument, got {err:?}"
        );
        assert!(!home.join("projects").exists(), "no project storage may be created");
        assert!(!repo_dir.join(".xtrace").exists(), "no repository pointer may be created");
    }
}
