//! `xtrace export` (lane W). C0 stub: returns a typed not-implemented error.

use std::path::PathBuf;

use crate::error::CliError;

/// Arguments for `xtrace export`.
#[derive(Clone, Debug, clap::Args)]
pub struct ExportArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
    /// Export format: openapi, postman, curl or bundle.
    #[arg(long, value_name = "FORMAT")]
    pub format: Option<String>,
    /// Output path.
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
    /// Operations to include (repeatable).
    #[arg(long, value_name = "OPERATION")]
    pub operations: Vec<String>,
    /// Catalog revision to export.
    #[arg(long, value_name = "REVISION")]
    pub revision: Option<String>,
    /// Preview without writing.
    #[arg(long)]
    pub preview: bool,
}

/// Runs `xtrace export`.
pub async fn run(_args: ExportArgs) -> Result<i32, CliError> {
    Err(CliError::NotImplemented { command: "export" })
}
