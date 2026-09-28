//! CLI subcommand definitions and dispatch.
//!
//! Each subcommand parses its own arguments, builds the corresponding
//! application [`Command`] or [`Query`], invokes the application
//! facade, and renders the result. The dispatcher owns no policy; the
//! application facade is the single source of truth for what the
//! CLI is allowed to do.

use std::path::PathBuf;

use clap::Subcommand;
use serde::Serialize;
use xtrace_application::{
    Application, Command, GetStoreStatus, InitializeProject, OpenProject, Query, RequestContext,
};
use xtrace_domain::WallTime;
use xtrace_store::CURRENT_SCHEMA_VERSION;
use xtrace_store::SqliteProjectRepository;

use crate::error::CliError;
use crate::output::write_success;
use crate::store_paths::StoreLocator;

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
        /// Idempotency key. Repeated runs with the same key return
        /// the original receipt.
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
    let locator = StoreLocator::from_project_dir(&project_dir)?;
    let requested_at = WallTime::now();
    let ctx = RequestContext::new(env_user(), requested_at);

    // Build the application facade before opening the store so a
    // validation failure (e.g. empty display name) does not touch the
    // filesystem.
    let store = locator.open_store()?;
    let repository = SqliteProjectRepository::new(&store);
    let app = Application::new(repository, CURRENT_SCHEMA_VERSION, 1, 0);
    let canonical = locator.project_dir.display().to_string();
    let resolved_display_name = if display_name.trim().is_empty() {
        locator
            .project_dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| canonical.clone())
    } else {
        display_name
    };
    let resolved_idempotency_key = if idempotency_key.trim().is_empty() {
        format!("xtrace-init-{}", locator.project_dir.display())
    } else {
        idempotency_key
    };
    let receipt = app.execute(
        Command::InitializeProject(InitializeProject {
            canonical_repo_path: canonical,
            display_name: resolved_display_name,
            idempotency_key: resolved_idempotency_key,
        }),
        &ctx,
    )?;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let document = InitDocument::from_receipt(&receipt, &locator);
    write_success(&mut handle, &document)?;
    Ok(())
}

fn open(project_dir: PathBuf, idempotency_key: String) -> Result<(), CliError> {
    let locator = StoreLocator::from_project_dir(&project_dir)?;
    let requested_at = WallTime::now();
    let ctx = RequestContext::new(env_user(), requested_at);

    let store = locator.open_store()?;
    let repository = SqliteProjectRepository::new(&store);
    let app = Application::new(repository, CURRENT_SCHEMA_VERSION, 1, 0);
    let canonical = locator.project_dir.display().to_string();
    let resolved_idempotency_key = if idempotency_key.trim().is_empty() {
        format!("xtrace-open-{}", locator.project_dir.display())
    } else {
        idempotency_key
    };
    let receipt = app.execute(
        Command::OpenProject(OpenProject {
            canonical_repo_path: canonical,
            idempotency_key: resolved_idempotency_key,
        }),
        &ctx,
    )?;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let document = OpenDocument::from_receipt(&receipt, &locator);
    write_success(&mut handle, &document)?;
    Ok(())
}

fn status(project_dir: PathBuf) -> Result<(), CliError> {
    let locator = StoreLocator::from_project_dir(&project_dir)?;
    let requested_at = WallTime::now();
    let ctx = RequestContext::new(env_user(), requested_at);

    let store = locator.open_store()?;
    let repository = SqliteProjectRepository::new(&store);
    let app = Application::new(repository, CURRENT_SCHEMA_VERSION, 1, 0);
    let result = app.query(Query::GetStoreStatus(GetStoreStatus), &ctx)?;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    match result {
        xtrace_application::QueryResult::StoreStatus(report) => {
            let document =
                StatusDocument::from_report(report, store.bootstrap().schema_version, &locator);
            write_success(&mut handle, &document)?;
        }
        xtrace_application::QueryResult::Project(_) => {
            unreachable!("GetStoreStatus must produce a StoreStatus variant")
        }
    }
    Ok(())
}

/// Best-effort "who ran the command" placeholder. The CLI does not
/// authenticate; future slices replace this with the resolved
/// principal from the daemon.
fn env_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
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
    pub schema_version: u32,
}

impl InitDocument {
    fn from_receipt(receipt: &xtrace_application::CommandReceipt, locator: &StoreLocator) -> Self {
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
                project_dir: locator.project_dir.display().to_string(),
                database_path: locator.database_path.display().to_string(),
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
    fn from_receipt(receipt: &xtrace_application::CommandReceipt, locator: &StoreLocator) -> Self {
        match receipt {
            xtrace_application::CommandReceipt::ProjectOpened { project_id, idempotency_key } => {
                Self {
                    kind: "project_opened",
                    project_id: project_id.to_string(),
                    idempotency_key: idempotency_key.clone(),
                    project_dir: locator.project_dir.display().to_string(),
                    database_path: locator.database_path.display().to_string(),
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
        locator: &StoreLocator,
    ) -> Self {
        Self {
            kind: "store_status",
            project_dir: locator.project_dir.display().to_string(),
            database_path: locator.database_path.display().to_string(),
            store_schema_version: schema_version,
            capabilities: report.capabilities,
            projects: report.projects,
        }
    }
}
