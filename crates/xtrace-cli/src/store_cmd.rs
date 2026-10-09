//! `xtrace store ...` (lane P). C stub: returns a typed not-implemented error.

use std::path::PathBuf;

use clap::Subcommand;

use crate::error::CliError;

/// Shared arguments for `xtrace store` subcommands.
#[derive(Clone, Debug, clap::Args)]
pub struct StoreArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

/// Arguments for `xtrace store migrate`.
#[derive(Clone, Debug, clap::Args)]
pub struct MigrateArgs {
    /// Common arguments.
    #[command(flatten)]
    pub common: StoreArgs,
    /// Report the migrations that would run without applying them.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

/// `xtrace store` subcommands.
#[derive(Clone, Debug, Subcommand)]
pub enum StoreCommand {
    /// Write a verified backup of the project store.
    Backup(StoreArgs),
    /// Verify the project store and its objects.
    Verify(StoreArgs),
    /// Restore the project store from a backup.
    Restore(StoreArgs),
    /// Migrate the project store schema.
    Migrate(MigrateArgs),
}

/// Runs `xtrace store <command>`.
pub async fn run(command: StoreCommand) -> Result<i32, CliError> {
    let name = match command {
        StoreCommand::Backup(_) => "store backup",
        StoreCommand::Verify(_) => "store verify",
        StoreCommand::Restore(_) => "store restore",
        StoreCommand::Migrate(_) => "store migrate",
    };
    Err(CliError::NotImplemented { command: name })
}
