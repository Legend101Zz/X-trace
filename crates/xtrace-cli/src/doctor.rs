//! `xtrace doctor` (lane P). C0 stub: returns a typed not-implemented error.

use std::path::PathBuf;

use crate::error::CliError;

/// Arguments for `xtrace doctor`.
#[derive(Clone, Debug, clap::Args)]
pub struct DoctorArgs {
    /// Path to the repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// Write a diagnostic bundle to this path.
    #[arg(long, value_name = "PATH")]
    pub bundle: Option<PathBuf>,
    /// Confirm without prompting.
    #[arg(long)]
    pub yes: bool,
}

/// Runs `xtrace doctor`.
pub async fn run(_args: DoctorArgs) -> Result<i32, CliError> {
    Err(CliError::NotImplemented { command: "doctor" })
}
