//! Explicit foreground composition for the experimental browser viewer.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde::Serialize;
use xtrace_domain::ProjectId;
use xtrace_store::SqliteRecordingReader;

use crate::commands::open_recording_reader;
use crate::error::CliError;
use crate::output::write_success_line;
use crate::paths::read_env_path;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ViewerReadyDocument {
    #[serde(flatten)]
    readiness: xtrace_daemon::ViewerReadiness,
    browser_launch: &'static str,
}

/// Composes the read-only project store with the daemon viewer and owns its
/// foreground lifetime until Ctrl+C or SIGTERM.
pub async fn run(project_dir: PathBuf, no_browser: bool) -> Result<(), CliError> {
    let (project_id, reader, _) = open_recording_reader(&project_dir, &read_env_path)?;
    start_viewer(project_id, reader, no_browser).await
}

async fn start_viewer(
    project_id: ProjectId,
    reader: SqliteRecordingReader,
    no_browser: bool,
) -> Result<(), CliError> {
    let bound = xtrace_daemon::BoundViewer::bind(
        xtrace_application::RecordingQueryService::new(reader.clone()),
        xtrace_application::ObservedEndpointQueryService::new(reader),
        project_id,
    )
    .await
    .map_err(|_| CliError::InvalidArgument("could not bind experimental viewer".to_owned()))?;
    let readiness = bound.readiness();
    let browser_launch = if no_browser {
        "not_requested"
    } else if launch_browser(&readiness.url) {
        "requested"
    } else {
        "unavailable"
    };
    let output = ViewerReadyDocument { readiness, browser_launch };
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    write_success_line(&mut handle, &output)?;
    handle.flush()?;
    drop(handle);
    bound.serve(wait_for_shutdown()).await.map_err(|_| {
        CliError::InvalidArgument("experimental viewer stopped after a listener failure".to_owned())
    })
}

fn launch_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    let mut command = Command::new("open");
    #[cfg(target_os = "linux")]
    let mut command = Command::new("xdg-open");
    #[cfg(target_os = "windows")]
    let mut command = Command::new("rundll32");
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return false;

    #[cfg(target_os = "windows")]
    command.args(["url.dll,FileProtocolHandler"]);
    command
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_ok()
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        if let Ok(mut terminate) = terminate {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
