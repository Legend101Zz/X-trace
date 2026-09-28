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
use xtrace_domain::WallTime;
use xtrace_store::{CURRENT_SCHEMA_VERSION, SqliteIdempotencyStore, SqliteProjectRepository};
use xtrace_store::{SqliteStore, StoreErrorKind};

use crate::error::CliError;
use crate::output::write_success;
use crate::paths::{
    RepositoryPointer, UserDataPaths, precreate_database_file, restrict_database_file,
    restrict_project_dir, secure_project_dir,
};

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
            init(project_dir, display_name, idempotency_key, &crate::paths::read_env_path)
        }
        XtraceCommand::Open { project_dir, idempotency_key } => {
            open(project_dir, idempotency_key, &crate::paths::read_env_path)
        }
        XtraceCommand::Status { project_dir } => status(project_dir, &crate::paths::read_env_path),
    }
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
fn resolve_data_home<F>(
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
    // Honour an existing pointer so re-running `init` against the
    // same repository uses the original project identifier. Only a
    // missing pointer is treated as "fresh init"; every other
    // pointer failure (corrupt body, unsupported schema version,
    // relative `data_home`, I/O error) propagates so a corrupt
    // pointer cannot be silently overwritten.
    let existing_pointer = match RepositoryPointer::read(&repo) {
        Ok(pointer) => Some(pointer),
        Err(CliError::ProjectDirectoryMissing(_)) => None,
        Err(err) => return Err(err),
    };
    let user_data_home = resolve_data_home(existing_pointer.as_ref(), env_reader)?;
    let project_id =
        existing_pointer.as_ref().map(|pointer| pointer.project_id).unwrap_or_default();
    let project_directory = UserDataPaths::project_dir_with_home(&user_data_home, project_id)?;
    let database_path = UserDataPaths::database_path_with_home(&user_data_home, project_id)?;
    // Create the project directory and tighten its permissions to
    // owner-only *before* SQLite creates the database file. The
    // directory's `0700` mode prevents another user on the host
    // from traversing into the project before the database file is
    // born; the file's `0600` mode below closes the same window on
    // the file itself.
    std::fs::create_dir_all(&project_directory)
        .map_err(|err| CliError::StoreUnavailable(format!("create project dir: {err}")))?;
    restrict_project_dir(&project_directory)?;
    // Pre-create the database file with mode `0600` before SQLite
    // opens it so the file is never readable by another user, even
    // for a single instant. The helper verifies the mode after
    // creation so a restrictive umask cannot strip the bits.
    precreate_database_file(&database_path)?;
    let requested_at = WallTime::now();
    let ctx = RequestContext::new(env_user(), requested_at);

    let store = SqliteStore::open(
        &database_path,
        xtrace_store::OpenOptions::default().with_correlation_id(ctx.correlation_id),
    )
    .map_err(map_store_error)?;
    // Defensive re-tightening: the precreate step already set
    // `0600`, but a future change to the open path must not be
    // able to widen the file's permissions silently.
    restrict_database_file(&database_path)?;
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
    // returns success. If `pointer.write` fails, the local database
    // has been initialized but the repository has no pointer file;
    // a follow-up `init` returns the idempotency receipt and re-
    // attempts the pointer write once the underlying I/O error is
    // resolved. The repository is *not* rolled back to an
    // uninitialized state.
    let pointer = RepositoryPointer { schema_version: 1, project_id, data_home: user_data_home };
    pointer.write(&repo)?;

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let document = InitDocument::from_receipt(&receipt, &pointer, &database_path);
    write_success(&mut handle, &document)?;
    Ok(())
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
    let requested_at = WallTime::now();
    let ctx = RequestContext::new(env_user(), requested_at);

    let store = SqliteStore::open(
        &database_path,
        xtrace_store::OpenOptions::default()
            .with_must_exist(true)
            .with_correlation_id(ctx.correlation_id),
    )
    .map_err(map_store_error)?;
    // Defensively tighten the project directory and database file
    // permissions in case the directory was created by an older
    // binary that did not enforce owner-only access. Fails closed.
    secure_project_dir(&project_directory)?;
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
            let store = SqliteStore::open(
                &database_path,
                xtrace_store::OpenOptions::default()
                    .with_must_exist(true)
                    .with_correlation_id(ctx.correlation_id),
            )
            .map_err(map_store_error)?;
            secure_project_dir(&project_directory)?;
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
    use std::collections::HashMap;
    use xtrace_domain::ProjectId;

    fn tempdir(label: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("xtrace-cli-commands-{label}-{nanos}"));
        std::fs::create_dir_all(&path).unwrap();
        path
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
            matches!(err, CliError::StoreUnavailable(_)),
            "open must fail without mutating: {err:?}"
        );
        assert!(!home.join("projects").exists(), "user-data directory must not be created");
        // `status` follows the same discipline.
        let err = status(repo_dir.clone(), &env_reader).unwrap_err();
        assert!(
            matches!(err, CliError::StoreUnavailable(_)),
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
            assert!(matches!(open_err, CliError::StoreUnavailable(_)));
            let status_err = status(repo_dir.clone(), &env_reader).unwrap_err();
            assert!(matches!(status_err, CliError::StoreUnavailable(_)));
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
            assert!(matches!(err, CliError::StoreUnavailable(_)));
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
    fn fresh_init_fails_after_storage_creation_keeps_owner_only_modes() {
        // Regression test for the permission ordering on the error
        // path of a *fresh* init: a display name over 128 bytes is
        // rejected by the application's validation after the project
        // directory and database file have already been created and
        // restricted. The fresh project directory and database file
        // must remain `0700` and `0600` respectively; the user-data
        // directory must contain exactly one project.
        use std::os::unix::fs::PermissionsExt as _;
        let repo_dir = tempdir("fresh-fail");
        std::fs::create_dir_all(&repo_dir).expect("repo");
        let home = tempdir("fresh-fail-home");
        let projects_root = home.join("projects");
        let mut values: HashMap<&'static str, PathBuf> = HashMap::new();
        values.insert("XTRACE_DATA_HOME", home.clone());
        values.insert("HOME", repo_dir.clone());
        let env_reader = reader(values);
        let oversized = "x".repeat(129);
        let err = init(repo_dir.clone(), oversized, String::new(), &env_reader).unwrap_err();
        assert!(
            matches!(err, CliError::App(ref app) if app.category == xtrace_domain::ErrorCategory::Validation),
            "oversized display name must surface as Validation, got {err:?}"
        );
        let project_dir = std::fs::read_dir(&projects_root)
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
        assert_eq!(
            dir_mode, 0o700,
            "fresh project directory must be 0700 after validation failure"
        );
        assert_eq!(db_mode, 0o600, "fresh database file must be 0600 after validation failure");
    }
}
