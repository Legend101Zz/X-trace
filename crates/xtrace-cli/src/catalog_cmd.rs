//! `xtrace catalog ...` (lane K): read the stored catalog.
//!
//! Every subcommand is read-only and prints one JSON document with `--json`, or a short text
//! table. The catalog holds what static scans claimed; nothing here asserts that an endpoint is
//! live or removed (an operation a later scan did not see is `unknown`).

use std::io::Write;
use std::path::PathBuf;

use clap::Subcommand;
use serde::Serialize;
use xtrace_application::catalog_discovery::history::{
    CatalogHistoryService, HistoryError, OperationView, RevisionEntry,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{CatalogRevisionId, ProjectId};

use crate::error::CliError;
use crate::output::write_success;

/// Shared arguments for `xtrace catalog` subcommands.
#[derive(Clone, Debug, clap::Args)]
pub struct CatalogArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// Revision to read; defaults to the newest.
    #[arg(long, value_name = "ID")]
    pub revision: Option<String>,
    /// Most rows to return for history and runs.
    #[arg(long, value_name = "N", default_value_t = 50)]
    pub limit: u32,
}

/// Arguments for `xtrace catalog diff`.
#[derive(Clone, Debug, clap::Args)]
pub struct DiffArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// Older revision; defaults to the parent of `--to`.
    #[arg(long, value_name = "ID")]
    pub from: Option<String>,
    /// Newer revision; defaults to the newest.
    #[arg(long, value_name = "ID")]
    pub to: Option<String>,
}

/// `xtrace catalog` subcommands.
#[derive(Clone, Debug, Subcommand)]
pub enum CatalogCommand {
    /// List the operations of a catalog revision.
    List(CatalogArgs),
    /// Show catalog revision history, newest first.
    History(CatalogArgs),
    /// Diff two catalog revisions of one scope.
    Diff(DiffArgs),
    /// List catalog conflicts of a revision.
    Conflicts(CatalogArgs),
    /// List catalog discovery runs, including incomplete ones.
    Runs(CatalogArgs),
    /// Reconcile a revision with the endpoints recordings were linked to.
    Reconcile(CatalogArgs),
}

fn invalid(message: impl Into<String>) -> CliError {
    CliError::InvalidArgument(message.into())
}

fn parse_revision(value: Option<&str>) -> Result<Option<CatalogRevisionId>, CliError> {
    value
        .map(|text| {
            uuid::Uuid::parse_str(text)
                .map(CatalogRevisionId::from_uuid)
                .map_err(|_| invalid("a revision id is a UUID"))
        })
        .transpose()
}

fn map_error(error: HistoryError) -> CliError {
    match error {
        HistoryError::RevisionNotFound
        | HistoryError::NoRevisions
        | HistoryError::ScopeMismatch => invalid(error.to_string()),
        HistoryError::Port(_) => CliError::StoreUnavailable(error.to_string()),
    }
}

#[cfg(unix)]
fn open(
    project_dir: &std::path::Path,
) -> Result<
    (
        CatalogHistoryService<xtrace_store::catalog_history_store::SqliteCatalogHistoryStore>,
        ProjectId,
    ),
    CliError,
> {
    let env_reader = crate::paths::read_env_path;
    let preflight = crate::daemon::preflight_project(project_dir, &env_reader)?;
    let validated = crate::daemon::open_validated_project(preflight)?;
    Ok((
        CatalogHistoryService::new(
            xtrace_store::catalog_history_store::SqliteCatalogHistoryStore::new(validated.store),
        ),
        validated.project_id,
    ))
}

#[cfg(not(unix))]
fn open(
    _project_dir: &std::path::Path,
) -> Result<
    (
        CatalogHistoryService<xtrace_store::catalog_history_store::SqliteCatalogHistoryStore>,
        ProjectId,
    ),
    CliError,
> {
    Err(CliError::StoreUnavailable("the catalog needs the Unix private-storage layer".to_owned()))
}

fn emit<T: Serialize>(
    json: bool,
    document: &T,
    text: impl FnOnce(&mut dyn Write) -> std::io::Result<()>,
) -> Result<i32, CliError> {
    let mut stdout = std::io::stdout().lock();
    let written = if json { write_success(&mut stdout, document) } else { text(&mut stdout) };
    written.map_err(|_| invalid("could not write output"))?;
    Ok(0)
}

fn revision_line(out: &mut dyn Write, entry: &RevisionEntry) -> std::io::Result<()> {
    writeln!(
        out,
        "{}  #{}  {} operations  {}  {}",
        entry.revision_id,
        entry.ordinal,
        entry.operation_count,
        entry.created_at,
        entry.pack_status
    )
}

fn operation_line(out: &mut dyn Write, op: &OperationView) -> std::io::Result<()> {
    writeln!(
        out,
        "{:7} {}  [{}]  {}  {}:{}{}",
        op.method,
        op.route_template,
        op.change_kind.as_str(),
        op.provenance.join("+"),
        op.source_path.as_deref().unwrap_or("-"),
        op.source_line.unwrap_or(0),
        if op.limitation_codes.is_empty() {
            String::new()
        } else {
            format!("  ({})", op.limitation_codes.join(", "))
        }
    )
}

/// Runs `xtrace catalog <command>`.
pub async fn run(command: CatalogCommand) -> Result<i32, CliError> {
    match command {
        CatalogCommand::History(args) => {
            let (service, project) = open(&args.project_dir)?;
            let revisions = service.history(project, args.limit).map_err(map_error)?;
            emit(args.json, &serde_json::json!({ "revisions": revisions }), |out| {
                if revisions.is_empty() {
                    writeln!(out, "no catalog revisions; run `xtrace scan`")?;
                }
                revisions.iter().try_for_each(|entry| revision_line(out, entry))
            })
        }
        CatalogCommand::Runs(args) => {
            let (service, project) = open(&args.project_dir)?;
            let runs = service.runs(project, args.limit).map_err(map_error)?;
            emit(args.json, &serde_json::json!({ "runs": runs }), |out| {
                for run in &runs {
                    writeln!(
                        out,
                        "{}  {}  {} accepted, {} rejected{}",
                        run.run_id,
                        run.status,
                        run.accepted_claims,
                        run.rejected_claims,
                        run.revision_id.map_or(String::new(), |id| format!("  revision {id}"))
                    )?;
                }
                Ok(())
            })
        }
        CatalogCommand::List(args) => {
            let revision = parse_revision(args.revision.as_deref())?;
            let (service, project) = open(&args.project_dir)?;
            let (entry, operations) = service.operations(project, revision).map_err(map_error)?;
            emit(
                args.json,
                &serde_json::json!({ "revision": entry, "operations": operations }),
                |out| {
                    revision_line(out, &entry)?;
                    operations.iter().try_for_each(|op| operation_line(out, op))
                },
            )
        }
        CatalogCommand::Conflicts(args) => {
            let revision = parse_revision(args.revision.as_deref())?;
            let (service, project) = open(&args.project_dir)?;
            let (entry, conflicts) = service.conflicts(project, revision).map_err(map_error)?;
            emit(
                args.json,
                &serde_json::json!({ "revision": entry, "conflicts": conflicts }),
                |out| {
                    revision_line(out, &entry)?;
                    if conflicts.is_empty() {
                        writeln!(out, "no conflicts")?;
                    }
                    for conflict in &conflicts {
                        writeln!(
                            out,
                            "{} {} {}: {}",
                            conflict.kind,
                            conflict.method,
                            conflict.route_template,
                            conflict.handlers.join(", ")
                        )?;
                    }
                    Ok(())
                },
            )
        }
        CatalogCommand::Diff(args) => {
            let from = parse_revision(args.from.as_deref())?;
            let to = parse_revision(args.to.as_deref())?;
            let (service, project) = open(&args.project_dir)?;
            let diff = service.diff(project, from, to).map_err(map_error)?;
            emit(args.json, &diff, |out| {
                writeln!(out, "diff {} -> {}", diff.from, diff.to)?;
                let counts: Vec<String> =
                    diff.counts.iter().map(|(kind, n)| format!("{n} {kind}")).collect();
                writeln!(out, "{}", counts.join(", "))?;
                for entry in &diff.entries {
                    writeln!(
                        out,
                        "{:9} {:7} {}",
                        entry.change.as_str(),
                        entry.method,
                        entry.route_template
                    )?;
                }
                writeln!(out, "{}", diff.note)
            })
        }
        CatalogCommand::Reconcile(args) => {
            let revision = parse_revision(args.revision.as_deref())?;
            let (service, project) = open(&args.project_dir)?;
            let result =
                service.reconcile_with_observations(project, revision).map_err(map_error)?;
            emit(args.json, &result, |out| {
                writeln!(
                    out,
                    "{} confirmed, {} unobserved, {} undeclared, {} unresolved",
                    result.confirmed, result.unobserved, result.undeclared, result.unresolved
                )?;
                for row in &result.reconciliation.rows {
                    writeln!(
                        out,
                        "{:15} {:7} {}  ({} recordings)",
                        format!("{:?}", row.status),
                        row.method,
                        row.route_template,
                        row.recording_count
                    )?;
                }
                writeln!(out, "{}", result.note)
            })
        }
    }
}
