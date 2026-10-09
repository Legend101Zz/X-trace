//! `xtrace retention ...` (lane P). C stub: returns a typed not-implemented error.

use std::path::PathBuf;

use clap::Subcommand;

use crate::error::CliError;

/// Shared arguments for `xtrace retention` subcommands.
#[derive(Clone, Debug, clap::Args)]
pub struct RetentionArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

/// Arguments for `xtrace retention apply`.
#[derive(Clone, Debug, clap::Args)]
pub struct ApplyArgs {
    /// Common arguments.
    #[command(flatten)]
    pub common: RetentionArgs,
    /// Digest of the previewed deletion set being applied.
    #[arg(long = "preview-digest", value_name = "DIGEST")]
    pub preview_digest: String,
}

/// `xtrace retention` subcommands.
#[derive(Clone, Debug, Subcommand)]
pub enum RetentionCommand {
    /// Show what a retention run would delete without deleting anything.
    Preview(RetentionArgs),
    /// Apply a previously previewed deletion set.
    Apply(ApplyArgs),
}

/// Runs `xtrace retention <command>`.
pub async fn run(command: RetentionCommand) -> Result<i32, CliError> {
    let name = match command {
        RetentionCommand::Preview(_) => "retention preview",
        RetentionCommand::Apply(_) => "retention apply",
    };
    Err(CliError::NotImplemented { command: name })
}
