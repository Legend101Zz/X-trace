//! CLI subcommand definitions and dispatch.
//!
//! Each subcommand parses its own arguments, builds the corresponding
//! application [`Command`] or [`Query`], invokes the application
//! facade, and renders the result. The dispatcher owns no policy; the
//! application facade is the single source of truth for what the
//! CLI is allowed to do.

use std::path::{Path, PathBuf};

use clap::Subcommand;
use serde::Serialize;
use xtrace_application::{
    Application, Command, GetStoreStatus, InitializeProject, OpenProject, Query, RequestContext,
};
use xtrace_domain::{ProjectId, WallTime};
use xtrace_store::{CURRENT_SCHEMA_VERSION, SqliteIdempotencyStore, SqliteProjectRepository};
use xtrace_store::{SqliteStore, StoreErrorKind};

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
    },
    /// Emit a machine-readable status report for the local store.
    Status {
        /// Path to the repository root.
        #[arg(long = "project-dir", value_name = "DIR")]
        project_dir: PathBuf,
    },
}

/// Dispatches the supplied subcommand and writes the result to
/// stdout. Errors propagate as [`CliError`] so [`main`] can render
/// them.
pub fn run(command: XtraceCommand) -> Result<(), CliError> {
    match command {
        XtraceCommand::Init { project_dir, display_name, idempotency_key } => {
            init(project_dir, display_name, idempotency_key)
        }
        XtraceCommand::Open { project_dir, idempotency_key } => open(project_dir, idempotency_key),
        XtraceCommand::Status { project_dir } => status(project_dir),
    }
}

fn init(
    project_dir: PathBuf,
    display_name: String,
    idempotency_key: String,
) -> Result<(), CliError> {
    let repo = resolve_repo(&project_dir)?;
    let user_data_home = UserDataPaths::home()?;
    // Honour an existing pointer so re-running `init` against the
    // same repository uses the original project identifier. The
    // application facade's idempotency contract then either returns
    // the original receipt (same canonical input) or surfaces
    // `XTR-COMMAND-409` (different canonical input).
    let project_id = match RepositoryPointer::read(&repo) {
        Ok(pointer) => pointer.project_id,
        Err(CliError::ProjectDirectoryMissing(_)) => ProjectId::new(),
        Err(err) => return Err(err),
    };
    let project_directory = UserDataPaths::project_dir(project_id)?;
    std::fs::create_dir_all(&project_directory)
        .map_err(|err| CliError::StoreUnavailable(format!("create project dir: {err}")))?;
    let database_path = UserDataPaths::database_path(project_id)?;
    let requested_at = WallTime::now();
    let ctx = RequestContext::new(env_user(), requested_at);

    let store = SqliteStore::open(&database_path, xtrace_store::OpenOptions::default())
        .map_err(map_store_error)?;
    let repository = SqliteProjectRepository::new(&store);
    let idempotency = SqliteIdempotencyStore::new(&store);
    let app = Application::new(repository, idempotency, CURRENT_SCHEMA_VERSION, 1, 0);

    let canonical = repo.display().to_string();
    let resolved_display_name = if display_name.trim().is_empty() {
        repo.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| canonical.clone())
    } else {
        display_name
    };
    let resolved_idempotency_key = if idempotency_key.trim().is_empty() {
        format!("xtrace-init-{canonical}")
    } else {
        idempotency_key
    };
    let receipt = app
        .execute(
            Command::InitializeProject(InitializeProject {
                canonical_repo_path: canonical,
                display_name: resolved_display_name,
                idempotency_key: resolved_idempotency_key,
                project_id,
            }),
            &ctx,
        )
        .map_err(CliError::from)?;

    // Persist the repository pointer only after the application
    // returns success. If `init` fails the repository stays
    // uninitialized so a retry starts from a clean slate.
    let pointer = RepositoryPointer { schema_version: 1, project_id, data_home: user_data_home };
    pointer.write(&repo)?;

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let document = InitDocument::from_receipt(&receipt, &pointer, &database_path);
    write_success(&mut handle, &document)?;
    Ok(())
}

fn open(project_dir: PathBuf, idempotency_key: String) -> Result<(), CliError> {
    let repo = resolve_repo(&project_dir)?;
    let pointer = RepositoryPointer::read(&repo)?;
    let database_path = UserDataPaths::database_path(pointer.project_id)?;
    let requested_at = WallTime::now();
    let ctx = RequestContext::new(env_user(), requested_at);

    let store = SqliteStore::open(&database_path, xtrace_store::OpenOptions::default())
        .map_err(map_store_error)?;
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
    let document = OpenDocument::from_receipt(&receipt, &pointer, &database_path);
    write_success(&mut handle, &document)?;
    Ok(())
}

fn status(project_dir: PathBuf) -> Result<(), CliError> {
    let repo = resolve_repo(&project_dir)?;
    let requested_at = WallTime::now();
    let ctx = RequestContext::new(env_user(), requested_at);

    // Status on an uninitialized repository reports the empty state
    // without opening or creating any database file. The check is
    // purely about the pointer file; the database is never touched
    // when the pointer is absent.
    let document = match RepositoryPointer::read(&repo) {
        Ok(pointer) => {
            let database_path = UserDataPaths::database_path(pointer.project_id)?;
            // Open read-by-side-effect: we need the bootstrap so the
            // report names the schema version actually present on
            // disk, but we never write from status.
            let store = SqliteStore::open(&database_path, xtrace_store::OpenOptions::default())
                .map_err(map_store_error)?;
            let repository = SqliteProjectRepository::new(&store);
            let idempotency = SqliteIdempotencyStore::new(&store);
            let app = Application::new(repository, idempotency, CURRENT_SCHEMA_VERSION, 1, 0);
            let result = app.query(Query::GetStoreStatus(GetStoreStatus), &ctx)?;
            match result {
                xtrace_application::QueryResult::StoreStatus(report) => {
                    StatusDocument::from_report(
                        report,
                        store.bootstrap().schema_version,
                        &pointer,
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

fn resolve_repo(project_dir: &Path) -> Result<PathBuf, CliError> {
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
fn map_store_error(err: xtrace_store::StoreError) -> CliError {
    match err.kind() {
        StoreErrorKind::Corruption | StoreErrorKind::SchemaIncompatible => {
            CliError::StoreCorrupted(err.message().to_string())
        }
        StoreErrorKind::SchemaNewer => CliError::StoreSchemaNewer(err.message().to_string()),
        StoreErrorKind::SchemaOlder => CliError::StoreSchemaOlder(err.message().to_string()),
        StoreErrorKind::Transport => CliError::StoreUnavailable(err.message().to_string()),
        StoreErrorKind::Busy => CliError::StoreUnavailable(err.message().to_string()),
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
                project_dir: pointer.data_home.display().to_string(),
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
        pointer: &RepositoryPointer,
        database_path: &Path,
    ) -> Self {
        match receipt {
            xtrace_application::CommandReceipt::ProjectOpened { project_id, idempotency_key } => {
                Self {
                    kind: "project_opened",
                    project_id: project_id.to_string(),
                    idempotency_key: idempotency_key.clone(),
                    project_dir: pointer.data_home.display().to_string(),
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
        pointer: &RepositoryPointer,
        database_path: &Path,
    ) -> Self {
        Self {
            kind: "store_status",
            initialized: true,
            project_dir: pointer.data_home.display().to_string(),
            database_path: database_path.display().to_string(),
            store_schema_version: schema_version,
            capabilities: report.capabilities,
            projects: report.projects,
        }
    }
}
