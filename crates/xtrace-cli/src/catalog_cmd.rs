//! `xtrace catalog ...` (lane K). C0 stub: returns a typed not-implemented error.

use std::path::PathBuf;

use clap::Subcommand;

use crate::error::CliError;

/// Shared arguments for `xtrace catalog` subcommands.
#[derive(Clone, Debug, clap::Args)]
pub struct CatalogArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

/// `xtrace catalog` subcommands.
#[derive(Clone, Debug, Subcommand)]
pub enum CatalogCommand {
    /// List catalog operations.
    List(CatalogArgs),
    /// Show catalog revision history.
    History(CatalogArgs),
    /// Diff two catalog revisions.
    Diff(CatalogArgs),
    /// List catalog conflicts.
    Conflicts(CatalogArgs),
    /// List catalog discovery runs.
    Runs(CatalogArgs),
}

/// Runs `xtrace catalog <command>`.
pub async fn run(command: CatalogCommand) -> Result<i32, CliError> {
    let name = match command {
        CatalogCommand::List(_) => "catalog list",
        CatalogCommand::History(_) => "catalog history",
        CatalogCommand::Diff(_) => "catalog diff",
        CatalogCommand::Conflicts(_) => "catalog conflicts",
        CatalogCommand::Runs(_) => "catalog runs",
    };
    Err(CliError::NotImplemented { command: name })
}
