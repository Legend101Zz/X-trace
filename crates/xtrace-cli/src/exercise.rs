//! `xtrace exercise ...` (lane W). C0 stub: returns a typed not-implemented error.

use std::path::PathBuf;

use clap::Subcommand;

use crate::error::CliError;

/// Shared arguments for `xtrace exercise` subcommands.
#[derive(Clone, Debug, clap::Args)]
pub struct ExerciseArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

/// Arguments for `xtrace exercise approve`.
#[derive(Clone, Debug, clap::Args)]
pub struct ApproveArgs {
    /// Common arguments.
    #[command(flatten)]
    pub common: ExerciseArgs,
    /// Hash of the plan being approved.
    #[arg(long = "plan-hash", value_name = "HASH")]
    pub plan_hash: String,
}

/// `xtrace exercise` subcommands.
#[derive(Clone, Debug, Subcommand)]
pub enum ExerciseCommand {
    /// Build an exercise plan.
    Plan(ExerciseArgs),
    /// Approve a plan by hash.
    Approve(ApproveArgs),
    /// Run an approved plan.
    Run(ExerciseArgs),
    /// Show a plan or run.
    Show(ExerciseArgs),
}

/// Runs `xtrace exercise <command>`.
pub async fn run(command: ExerciseCommand) -> Result<i32, CliError> {
    let name = match command {
        ExerciseCommand::Plan(_) => "exercise plan",
        ExerciseCommand::Approve(_) => "exercise approve",
        ExerciseCommand::Run(_) => "exercise run",
        ExerciseCommand::Show(_) => "exercise show",
    };
    Err(CliError::NotImplemented { command: name })
}
