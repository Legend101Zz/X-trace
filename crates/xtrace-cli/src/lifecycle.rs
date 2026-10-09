//! `xtrace record`, `stop`, `restart` (lane P). C0 stub: typed not-implemented errors.

use std::path::PathBuf;

use crate::error::CliError;

/// Arguments for `xtrace record`.
#[derive(Clone, Debug, clap::Args)]
pub struct RecordArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// Capture depth: `standard` or `focused`.
    #[arg(long = "capture-depth", value_name = "DEPTH", default_value = "standard")]
    pub capture_depth: String,
}

/// Arguments for `xtrace stop`.
#[derive(Clone, Debug, clap::Args)]
pub struct StopArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// Session to end.
    #[arg(long, value_name = "ID")]
    pub session: Option<String>,
}

/// Arguments for `xtrace restart`.
#[derive(Clone, Debug, clap::Args)]
pub struct RestartArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// Capture depth: `standard` or `focused`.
    #[arg(long = "capture-depth", value_name = "DEPTH", default_value = "standard")]
    pub capture_depth: String,
}

/// Runs `xtrace record`.
pub async fn run_record(_args: RecordArgs) -> Result<i32, CliError> {
    Err(CliError::NotImplemented { command: "record" })
}

/// Runs `xtrace stop`.
pub async fn run_stop(_args: StopArgs) -> Result<i32, CliError> {
    Err(CliError::NotImplemented { command: "stop" })
}

/// Runs `xtrace restart`.
pub async fn run_restart(_args: RestartArgs) -> Result<i32, CliError> {
    Err(CliError::NotImplemented { command: "restart" })
}
