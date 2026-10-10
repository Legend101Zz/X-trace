//! `xtrace export` argument surface; the implementation lives in `export_cmd`.

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
    /// Output directory (created private, mode 0700, if absent).
    #[arg(long, value_name = "DIR")]
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
    /// Emit OpenAPI as YAML instead of JSON.
    #[arg(long)]
    pub yaml: bool,
}

/// Runs `xtrace export`.
pub async fn run(args: ExportArgs) -> Result<i32, CliError> {
    crate::export_cmd::run(args).await
}
