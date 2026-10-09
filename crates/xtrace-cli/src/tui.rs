//! `xtrace tui` (lane X). C0 stub: returns a typed not-implemented error.

use std::path::PathBuf;

use crate::error::CliError;

/// Arguments for `xtrace tui`.
#[derive(Clone, Debug, clap::Args)]
pub struct TuiArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

/// Runs `xtrace tui`.
pub async fn run(_args: TuiArgs) -> Result<i32, CliError> {
    Err(CliError::NotImplemented { command: "tui" })
}
