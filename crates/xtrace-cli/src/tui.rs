//! `xtrace tui` (lane X): the terminal viewer over the same application read facade as the
//! browser viewer. Interactive on a terminal; `--plain` renders one screen as text.

use std::path::PathBuf;

use xtrace_application::{
    DEFAULT_RECORDING_LIST_LIMIT, FrameNavigation, NavigationResult, NavigationUnavailable,
    RecordingCompletionEvidence, RecordingQueryService, ShowRecording,
};
use xtrace_domain::{CorrelationId, ProjectId, RecordingId};
use xtrace_store::SqliteRecordingReader;
use xtrace_tui::driver::{DEFAULT_SIZE, render_plain, run_interactive, terminal_size};
use xtrace_tui::{ClientError, FrameRow, NavAction, NavResult, RecordingRow, ReplayClient, Window};

use crate::commands::open_recording_reader;
use crate::error::CliError;
use crate::output::write_success;
use crate::paths::read_env_path;

/// Arguments for `xtrace tui`.
#[derive(Clone, Debug, clap::Args)]
pub struct TuiArgs {
    /// Path to the initialized repository root.
    #[arg(long = "project-dir", value_name = "DIR", default_value = ".")]
    pub project_dir: PathBuf,
    /// Render one screen as plain text (no escape sequences) and exit; works without a terminal.
    #[arg(long)]
    pub plain: bool,
    /// With `--plain`, open this recording instead of showing the list.
    #[arg(long, value_name = "RECORDING_ID")]
    pub recording: Option<String>,
    /// Emit the plain screen as one JSON document `{"rows": [...]}`; implies `--plain`.
    #[arg(long)]
    pub json: bool,
}

/// Events per window; also the page size used to find a navigation target.
const WINDOW_LIMIT: u32 = 500;
/// Pages scanned forward when a window is requested around a frame (no server `aroundFrame` yet).
const MAX_SCAN_PAGES: u32 = 40;

struct Facade {
    project_id: ProjectId,
    service: RecordingQueryService<SqliteRecordingReader>,
}

impl Facade {
    fn page(
        &self,
        recording_id: RecordingId,
        cursor: Option<String>,
    ) -> Result<xtrace_application::RecordingDetail, ClientError> {
        self.service
            .show(
                ShowRecording {
                    project_id: self.project_id,
                    recording_id,
                    limit: WINDOW_LIMIT,
                    cursor,
                },
                CorrelationId::new(),
            )
            .map_err(|_| ClientError("could not read this recording".to_owned()))
    }
}

fn completion_label(completion: RecordingCompletionEvidence) -> &'static str {
    match completion {
        RecordingCompletionEvidence::Complete => "complete",
        RecordingCompletionEvidence::Partial => "partial",
        RecordingCompletionEvidence::Invalid => "invalid",
        RecordingCompletionEvidence::Unavailable => "unavailable",
    }
}

fn unavailable_text(reason: NavigationUnavailable) -> &'static str {
    match reason {
        NavigationUnavailable::PartialFrontier => {
            "the recording is partial; events beyond the verified window may exist."
        }
        NavigationUnavailable::LegacyUnindexed => {
            "this recording predates the frame index, so no relationship is recorded."
        }
        NavigationUnavailable::DepthOverflow => "the frame is deeper than the indexed depth.",
        NavigationUnavailable::OrphanParent => "the parent frame was never observed.",
        NavigationUnavailable::NotNavigable => "this event is not a navigable frame.",
    }
}

fn nav_result(result: NavigationResult) -> NavResult {
    match result {
        NavigationResult::Target { frame_id } => NavResult::Target(frame_id.to_string()),
        NavigationResult::Boundary => NavResult::Boundary(None),
        NavigationResult::Unavailable { reason } => {
            NavResult::Unavailable(unavailable_text(reason).to_owned())
        }
    }
}

/// Slots follow `NavAction` order: previous, next, into, over, out.
fn nav_slots(navigation: FrameNavigation) -> [Option<NavResult>; 5] {
    [
        Some(nav_result(navigation.previous)),
        Some(nav_result(navigation.next)),
        Some(nav_result(navigation.into)),
        Some(nav_result(navigation.over)),
        Some(nav_result(navigation.out)),
    ]
}

impl ReplayClient for Facade {
    fn list_recordings(&self) -> Result<Vec<RecordingRow>, ClientError> {
        let page = self
            .service
            .list(
                xtrace_application::ListRecordings {
                    project_id: self.project_id,
                    limit: DEFAULT_RECORDING_LIST_LIMIT,
                    after: None,
                },
                CorrelationId::new(),
            )
            .map_err(|_| ClientError("could not list recordings".to_owned()))?;
        Ok(page
            .recordings
            .into_iter()
            .map(|r| RecordingRow {
                id: r.recording_id.to_string(),
                completion: completion_label(r.completion).to_owned(),
                event_count: r.event_count.parse().unwrap_or(0),
            })
            .collect())
    }

    fn window(&self, recording_id: &str, around: Option<&str>) -> Result<Window, ClientError> {
        let id: RecordingId = recording_id
            .parse()
            .map_err(|_| ClientError("that is not a recording id".to_owned()))?;
        let mut cursor = None;
        for _ in 0..MAX_SCAN_PAGES {
            let detail = self.page(id, cursor)?;
            let has_target = around.is_none_or(|target| {
                detail.events.iter().any(|e| e.frame_id.is_some_and(|f| f.to_string() == target))
            });
            if has_target || detail.next_cursor.is_none() {
                if !has_target {
                    return Err(ClientError(
                        "that frame is not in the recording's persisted events".to_owned(),
                    ));
                }
                let completion = if detail.next_cursor.is_some() {
                    format!(
                        "{}; more events exist beyond the {} shown",
                        completion_label(detail.completion),
                        detail.events.len()
                    )
                } else {
                    completion_label(detail.completion).to_owned()
                };
                let frames: Vec<FrameRow> = detail
                    .events
                    .into_iter()
                    .map(|e| FrameRow {
                        frame_id: e.frame_id.map(|f| f.to_string()),
                        sequence: e.sequence.parse().unwrap_or(0),
                        kind: e.kind,
                        symbol: e.symbol,
                        depth: e.depth,
                        navigation: nav_slots(e.navigation),
                    })
                    .collect();
                return Ok(Window {
                    recording_id: recording_id.to_owned(),
                    frames,
                    completion,
                    anchor_frame_id: around.map(str::to_owned),
                });
            }
            cursor = detail.next_cursor;
        }
        Err(ClientError(
            "that frame is further into the recording than this viewer scans".to_owned(),
        ))
    }

    fn navigate(&self, _: &str, _: &str, _: NavAction) -> Result<NavResult, ClientError> {
        // Every frame row already carries the server-resolved answer for all five steps.
        Err(ClientError("no navigation answer is available for this frame".to_owned()))
    }
}

/// An unknown recording is a bad argument; any other failure is a read failure of the store.
fn read_error(message: String) -> CliError {
    if message == "that recording is not in this project" {
        CliError::InvalidArgument(message)
    } else {
        CliError::StoreUnavailable(message)
    }
}

/// Runs `xtrace tui`.
pub async fn run(args: TuiArgs) -> Result<i32, CliError> {
    let (project_id, reader, _) = open_recording_reader(&args.project_dir, &read_env_path)?;
    let facade = Facade { project_id, service: RecordingQueryService::new(reader) };
    if args.recording.is_some() && !(args.plain || args.json) {
        return Err(CliError::InvalidArgument("--recording needs --plain or --json".to_owned()));
    }
    if args.plain || args.json {
        let size = terminal_size().unwrap_or(DEFAULT_SIZE);
        let text = render_plain(&facade, size, args.recording.as_deref()).map_err(read_error)?;
        if args.json {
            let rows: Vec<&str> = text.lines().collect();
            let mut stdout = std::io::stdout().lock();
            write_success(&mut stdout, &serde_json::json!({ "rows": rows }))?;
        } else {
            use std::io::Write as _;
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(text.as_bytes())?;
        }
        return Ok(0);
    }
    run_interactive(&facade).map_err(|error| CliError::StoreUnavailable(error.to_string()))?;
    Ok(0)
}
