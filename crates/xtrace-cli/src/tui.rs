//! `xtrace tui` (lane X): the terminal viewer over the same application read facade as the
//! browser viewer. Interactive on a terminal; `--plain` renders one screen as text.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

use xtrace_application::{
    DEFAULT_RECORDING_LIST_LIMIT, FieldRepresentation, FieldTruncation, FrameNavigation,
    ListObservedEndpoints, ListOperationRecordings, ListRecordings, MAX_OBSERVED_ENDPOINT_LIMIT,
    MAX_OBSERVED_RECORDING_LIMIT, NavigationResult, NavigationUnavailable,
    ObservedEndpointQueryService, PersistedBinding, PersistedEvent, PersistedOutcome,
    PersistedValue, RecordingCompletionEvidence, RecordingDetail, RecordingQueryService,
    ShowRecording,
};
use xtrace_domain::{CorrelationId, ProjectId, RecordingId};
use xtrace_store::SqliteRecordingReader;
use xtrace_tui::driver::{DEFAULT_SIZE, render_plain, run_interactive, terminal_size};
use xtrace_tui::{
    ClientError, FrameRow, NavAction, NavResult, RecordingRow, RecordingsPage, ReplayClient, Window,
};

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
/// Maximum head events inspected to locate an unlinked recording's `request_update` route.
const ROUTE_PROBE_LIMIT: u32 = 16;
/// Maximum entries kept in the local route cache to keep memory bounded.
const MAX_ROUTE_CACHE_ENTRIES: usize = 512;
const MAX_ROUTE_CHARS: usize = 256;
const MAX_OUTCOME_CHARS: usize = 160;
const MAX_LIMITATION_CHARS: usize = 128;
const MAX_GAP_REASON_CHARS: usize = 128;
const MAX_SOURCE_CHARS: usize = 160;
const MAX_BINDING_CHARS: usize = 160;
const MAX_BINDINGS_PER_FRAME: usize = 24;
const MAX_FIELD_TRUNCATIONS_PER_FRAME: usize = 16;

type OpenReaderFn =
    Box<dyn Fn(&Path) -> Result<(ProjectId, SqliteRecordingReader), CliError> + Send + Sync>;

#[derive(Clone)]
struct ReaderState {
    project_id: ProjectId,
    service: RecordingQueryService<SqliteRecordingReader>,
    endpoints: ObservedEndpointQueryService<SqliteRecordingReader>,
}

struct Facade {
    project_dir: PathBuf,
    opener: OpenReaderFn,
    list_limit: u32,
    state: RwLock<ReaderState>,
    route_cache: Mutex<HashMap<String, Option<String>>>,
}

impl Facade {
    fn open(project_dir: PathBuf, opener: OpenReaderFn, list_limit: u32) -> Result<Self, CliError> {
        let (project_id, reader) = opener(&project_dir)?;
        Ok(Self {
            project_dir,
            opener,
            list_limit,
            state: RwLock::new(ReaderState {
                project_id,
                service: RecordingQueryService::new(reader.clone()),
                endpoints: ObservedEndpointQueryService::new(reader),
            }),
            route_cache: Mutex::new(HashMap::new()),
        })
    }

    fn reader_state(&self) -> Result<ReaderState, ClientError> {
        self.state
            .read()
            .map(|guard| guard.clone())
            .map_err(|_| ClientError("recording reader state is unavailable".to_owned()))
    }

    fn page(
        &self,
        state: &ReaderState,
        recording_id: RecordingId,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<RecordingDetail, ClientError> {
        state
            .service
            .show(
                ShowRecording {
                    project_id: state.project_id,
                    recording_id,
                    limit,
                    cursor,
                    around_frame: None,
                },
                CorrelationId::new(),
            )
            .map_err(|_| ClientError("could not read this recording".to_owned()))
    }

    fn cached_route(&self, recording_id: &str) -> Option<Option<String>> {
        let cache = self.route_cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.get(recording_id).cloned()
    }

    fn cache_route(&self, recording_id: &str, route: Option<String>) {
        let mut cache = self.route_cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.len() >= MAX_ROUTE_CACHE_ENTRIES && !cache.contains_key(recording_id) {
            cache.clear();
        }
        cache.insert(recording_id.to_owned(), route);
    }

    fn resolve_route_for_list(
        &self,
        state: &ReaderState,
        recording_id: RecordingId,
        id_str: &str,
        has_events: bool,
        is_terminal: bool,
        linked: &HashMap<String, String>,
    ) -> Option<String> {
        if let Some(route) = linked.get(id_str) {
            let bounded = bound_text(route, MAX_ROUTE_CHARS);
            self.cache_route(id_str, Some(bounded.clone()));
            return Some(bounded);
        }
        if let Some(cached) = self.cached_route(id_str) {
            return cached;
        }
        if !has_events {
            return None;
        }
        let Ok(detail) = self.page(state, recording_id, None, ROUTE_PROBE_LIMIT) else {
            return None;
        };
        let route = extract_route_from_events(&detail.events);
        if route.is_some() || is_terminal {
            self.cache_route(id_str, route.clone());
        }
        route
    }
}

fn bound_text(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let count = text.chars().count();
    if count <= max_chars {
        text.to_owned()
    } else {
        let mut out: String = text.chars().take(max_chars - 1).collect();
        out.push('~');
        out
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

fn linked_routes(
    endpoints: &ObservedEndpointQueryService<SqliteRecordingReader>,
    project_id: ProjectId,
) -> HashMap<String, String> {
    let mut routes = HashMap::new();
    let Ok(endpoint_page) = endpoints.list_observed_endpoints(
        ListObservedEndpoints {
            project_id,
            limit: Some(MAX_OBSERVED_ENDPOINT_LIMIT),
            cursor: None,
        },
        CorrelationId::new(),
    ) else {
        return routes;
    };
    for ep in endpoint_page.items {
        let route_label =
            bound_text(&format!("{} {}", ep.method, ep.route_template), MAX_ROUTE_CHARS);
        let Ok(rec_page) = endpoints.list_operation_recordings(
            ListOperationRecordings {
                project_id,
                operation_id: ep.operation_id,
                limit: Some(MAX_OBSERVED_RECORDING_LIMIT),
                cursor: None,
            },
            CorrelationId::new(),
        ) else {
            continue;
        };
        for item in rec_page.items {
            routes.insert(item.recording_id.to_string(), route_label.clone());
        }
    }
    routes
}

fn extract_route_from_events(events: &[PersistedEvent]) -> Option<String> {
    let mut method_only = None;
    for event in events {
        if event.kind != "recording_event_kind:request_update" && event.kind != "request_update" {
            continue;
        }
        if let Some(symbol) = event.symbol.as_deref() {
            if let Some(rest) = symbol.strip_prefix("http.request ") {
                let trimmed = rest.trim();
                if !trimmed.is_empty() {
                    if trimmed.contains(' ') {
                        return Some(bound_text(trimmed, MAX_ROUTE_CHARS));
                    }
                    if method_only.is_none() {
                        method_only = Some(bound_text(trimmed, MAX_ROUTE_CHARS));
                    }
                }
            }
        }
        if method_only.is_none() {
            if let Some(method) = event.interaction.as_ref().and_then(|i| i.method.as_deref()) {
                let trimmed = method.trim();
                if !trimmed.is_empty() {
                    method_only = Some(bound_text(trimmed, MAX_ROUTE_CHARS));
                }
            }
        }
    }
    method_only
}

fn format_outcome(outcome: Option<&PersistedOutcome>) -> Option<String> {
    let outcome = outcome?;
    let mut text = outcome.kind.clone();
    if let Some(status) = outcome.http_status {
        let _ = write!(text, " {status}");
    }
    if let Some(exception) = &outcome.exception {
        let _ = write!(text, " ({})", exception.exception_type);
    }
    Some(bound_text(&text, MAX_OUTCOME_CHARS))
}

fn format_source_location(event: &PersistedEvent) -> Option<String> {
    // R4: `event.line` is populated only for `line_cursor` events; method extents carry start..end.
    if let Some(line) = event.line {
        return match &event.source {
            Some(src) => Some(bound_text(&format!("{}:{line}", src.path), MAX_SOURCE_CHARS)),
            None => Some(format!("line {line}")),
        };
    }
    let src = event.source.as_ref()?;
    let formatted = match src.end_line {
        Some(end) if end > src.start_line => format!("{}:{}-{}", src.path, src.start_line, end),
        _ => format!("{}:{}", src.path, src.start_line),
    };
    Some(bound_text(&formatted, MAX_SOURCE_CHARS))
}

fn format_bindings(bindings: &[PersistedBinding]) -> (Vec<String>, bool) {
    let mut summary = Vec::new();
    let mut has_truncated = false;
    for binding in bindings.iter().take(MAX_BINDINGS_PER_FRAME) {
        let formatted = match &binding.value {
            PersistedValue::Captured { shape, preview, .. } => {
                if preview.is_empty() {
                    format!("{} ({shape})", binding.name)
                } else {
                    format!("{} ({shape}): {}", binding.name, bound_text(preview, 80))
                }
            }
            PersistedValue::Redacted { rule_id, shape_hint } => match shape_hint {
                Some(hint) => format!("{}: [redacted by {rule_id}; {hint}]", binding.name),
                None => format!("{}: [redacted by {rule_id}]", binding.name),
            },
            PersistedValue::Truncated { preview, original_size_lower_bound, limit } => {
                has_truncated = true;
                format!(
                    "{}: [truncated {limit}/{original_size_lower_bound}B] {}",
                    binding.name,
                    bound_text(preview, 64)
                )
            }
            PersistedValue::Unavailable { reason } => {
                format!("{}: [unavailable: {reason}]", binding.name)
            }
            PersistedValue::Dropped { reason } => {
                format!("{}: [dropped: {reason}]", binding.name)
            }
        };
        summary.push(bound_text(&formatted, MAX_BINDING_CHARS));
    }
    if bindings.len() > MAX_BINDINGS_PER_FRAME {
        has_truncated = true;
        summary.push(format!(
            "... {} more bindings (truncated)",
            bindings.len() - MAX_BINDINGS_PER_FRAME
        ));
    }
    (summary, has_truncated)
}

fn format_field_truncations(truncations: &[FieldTruncation]) -> Vec<String> {
    let mut formatted: Vec<String> = truncations
        .iter()
        .take(MAX_FIELD_TRUNCATIONS_PER_FRAME)
        .map(|entry| {
            let repr = match entry.representation {
                FieldRepresentation::Truncated => "truncated",
                FieldRepresentation::Unavailable => "unavailable",
            };
            bound_text(
                &format!("{} ({repr}, {}B)", entry.field, entry.original_bytes),
                MAX_BINDING_CHARS,
            )
        })
        .collect();
    if truncations.len() > MAX_FIELD_TRUNCATIONS_PER_FRAME {
        formatted.push(format!(
            "... {} more truncated fields",
            truncations.len() - MAX_FIELD_TRUNCATIONS_PER_FRAME
        ));
    }
    formatted
}

fn map_frame_row(event: PersistedEvent) -> FrameRow {
    let gap_reason = event.gap.as_ref().map(|g| bound_text(&g.reason, MAX_GAP_REASON_CHARS));
    let gap_count = event.gap.as_ref().and_then(|g| g.count.parse::<u64>().ok());
    let source_location = format_source_location(&event);
    let (bindings_summary, binding_truncated) = format_bindings(&event.bindings);
    let field_truncations = format_field_truncations(&event.field_truncations);
    let source_truncated = event.source.as_ref().is_some_and(|s| s.truncated);
    let truncated = !event.field_truncations.is_empty() || binding_truncated || source_truncated;
    FrameRow {
        frame_id: event.frame_id.map(|f| f.to_string()),
        sequence: event.sequence.parse().unwrap_or(0),
        kind: event.kind,
        symbol: event.symbol,
        depth: event.depth,
        navigation: nav_slots(event.navigation),
        gap_reason,
        gap_count,
        source_location,
        bindings_summary,
        truncated,
        field_truncations,
    }
}

fn detail_completion_label(detail: &RecordingDetail) -> String {
    let base = completion_label(detail.completion);
    let shown = detail.events.len();
    match (detail.prev_cursor.is_some(), detail.next_cursor.is_some()) {
        (true, true) => {
            format!("{base}; earlier and later events exist beyond these {shown} shown")
        }
        (false, true) => format!("{base}; more events exist beyond the {shown} shown"),
        (true, false) => format!("{base}; earlier events exist before these {shown} shown"),
        (false, false) => base.to_owned(),
    }
}

impl ReplayClient for Facade {
    fn list_recordings(&self) -> Result<Vec<RecordingRow>, ClientError> {
        self.list_recordings_page(None).map(|page| page.recordings)
    }

    fn list_recordings_page(&self, after: Option<&str>) -> Result<RecordingsPage, ClientError> {
        let state = self.reader_state()?;
        let parsed_after = after
            .map(|token| {
                token
                    .parse::<RecordingId>()
                    .map_err(|_| ClientError("that recording list cursor is invalid".to_owned()))
            })
            .transpose()?;
        let page = state
            .service
            .list(
                ListRecordings {
                    project_id: state.project_id,
                    limit: self.list_limit,
                    after: parsed_after,
                },
                CorrelationId::new(),
            )
            .map_err(|_| ClientError("could not list recordings".to_owned()))?;
        let linked = linked_routes(&state.endpoints, state.project_id);
        let next_after = page.next_after.map(|id| id.to_string());
        let has_more = next_after.is_some();
        let recordings = page
            .recordings
            .into_iter()
            .map(|r| {
                let id_str = r.recording_id.to_string();
                let event_count = r.event_count.parse().unwrap_or(0);
                let is_terminal = matches!(
                    r.status,
                    xtrace_application::RecordingStatus::Complete
                        | xtrace_application::RecordingStatus::Partial
                        | xtrace_application::RecordingStatus::Invalid
                );
                let route = self.resolve_route_for_list(
                    &state,
                    r.recording_id,
                    &id_str,
                    event_count > 0,
                    is_terminal,
                    &linked,
                );
                RecordingRow {
                    id: id_str,
                    completion: completion_label(r.completion).to_owned(),
                    event_count,
                    route,
                    outcome: r.outcome_kind.map(|kind| bound_text(&kind, MAX_OUTCOME_CHARS)),
                }
            })
            .collect();
        Ok(RecordingsPage { recordings, next_after, has_more })
    }

    fn window(&self, recording_id: &str, around: Option<&str>) -> Result<Window, ClientError> {
        self.window_page(recording_id, around, None)
    }

    fn window_page(
        &self,
        recording_id: &str,
        around: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<Window, ClientError> {
        let id: RecordingId = recording_id
            .parse()
            .map_err(|_| ClientError("that is not a recording id".to_owned()))?;
        let state = self.reader_state()?;
        let detail = if let Some(cursor_token) = cursor {
            self.page(&state, id, Some(cursor_token.to_owned()), WINDOW_LIMIT)?
        } else {
            let mut scan_cursor = None;
            let mut matched = None;
            for _ in 0..MAX_SCAN_PAGES {
                let page = self.page(&state, id, scan_cursor, WINDOW_LIMIT)?;
                let has_target = around.is_none_or(|target| {
                    page.events.iter().any(|e| e.frame_id.is_some_and(|f| f.to_string() == target))
                });
                if has_target {
                    matched = Some(page);
                    break;
                }
                if page.next_cursor.is_none() {
                    return Err(ClientError(
                        "that frame is not in the recording's persisted events".to_owned(),
                    ));
                }
                scan_cursor = page.next_cursor;
            }
            matched.ok_or_else(|| {
                ClientError(
                    "that frame is further into the recording than this viewer scans".to_owned(),
                )
            })?
        };
        let mut route = extract_route_from_events(&detail.events);
        if route.is_none() {
            if let Some(Some(cached)) = self.cached_route(recording_id) {
                route = Some(cached);
            } else {
                let linked = linked_routes(&state.endpoints, state.project_id);
                if let Some(linked_route) = linked.get(recording_id) {
                    route = Some(bound_text(linked_route, MAX_ROUTE_CHARS));
                } else if cursor.is_some() || around.is_some() {
                    if let Ok(head) = self.page(&state, id, None, ROUTE_PROBE_LIMIT) {
                        route = extract_route_from_events(&head.events);
                    }
                }
            }
        }
        if let Some(found) = &route {
            self.cache_route(recording_id, Some(found.clone()));
        }
        let outcome = format_outcome(detail.outcome.as_ref());
        let limitations: Vec<String> =
            detail.limitations.iter().map(|code| bound_text(code, MAX_LIMITATION_CHARS)).collect();
        let completion = detail_completion_label(&detail);
        let prev_cursor = detail.prev_cursor;
        let next_cursor = detail.next_cursor;
        let frames: Vec<FrameRow> = detail.events.into_iter().map(map_frame_row).collect();
        Ok(Window {
            recording_id: recording_id.to_owned(),
            frames,
            completion,
            anchor_frame_id: around.map(str::to_owned),
            route,
            outcome,
            limitations,
            prev_cursor,
            next_cursor,
        })
    }

    fn navigate(&self, _: &str, _: &str, _: NavAction) -> Result<NavResult, ClientError> {
        // Every frame row already carries the server-resolved answer for all five steps.
        Err(ClientError("no navigation answer is available for this frame".to_owned()))
    }

    fn reconnect(&self) -> Result<(), ClientError> {
        let (project_id, reader) = (self.opener)(&self.project_dir)
            .map_err(|_| ClientError("could not reconnect to the recording store".to_owned()))?;
        let mut guard = self
            .state
            .write()
            .map_err(|_| ClientError("recording reader state is unavailable".to_owned()))?;
        *guard = ReaderState {
            project_id,
            service: RecordingQueryService::new(reader.clone()),
            endpoints: ObservedEndpointQueryService::new(reader),
        };
        drop(guard);
        self.route_cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
        Ok(())
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
    if args.recording.is_some() && !(args.plain || args.json) {
        return Err(CliError::InvalidArgument("--recording needs --plain or --json".to_owned()));
    }
    let opener: OpenReaderFn = Box::new(|project_dir| {
        let (project_id, reader, _) = open_recording_reader(project_dir, &read_env_path)?;
        Ok((project_id, reader))
    });
    let facade = Facade::open(args.project_dir, opener, DEFAULT_RECORDING_LIST_LIMIT)?;
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

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "unit tests construct private temporary stores and assert checked results"
)]
mod tests {
    use super::*;
    use prost::Message as _;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;
    use xtrace_application::recording::{
        AcceptedRecordingEvent, BeginRecording, EndpointObservationInput, FinishRecording,
        LIMITATION_CAPTURE_POLICY_NOT_ARMED, PersistRecordingSegment,
        RecordingPersistencePort as _, STANDARD_EVENT_CAP,
    };
    use xtrace_domain::{OutcomeKind, RecordingOutcome, RuntimeSessionId, WallTime};
    use xtrace_protocol::generated::agent::{
        BindingRole, CapturedValue as WireValue, CapturedValueCaptured, CapturedValueDropped,
        CapturedValueRedacted, CapturedValueTruncated, CapturedValueUnavailable, GapPayload,
        GapReason, NameOrigin, RecordingEvent, RecordingEventKind, SourceBinding, SourceRange,
        ValueBinding, ValueShape, captured_value::Value as WireVariant,
    };
    use xtrace_protocol::xtf::XtfEventEnvelope;
    use xtrace_store::{OpenOptions, SqliteRecordingPersistence, SqliteStore};

    struct TestProject {
        _root: tempfile::TempDir,
        repo: PathBuf,
        data_home: PathBuf,
        project_id: ProjectId,
    }

    impl TestProject {
        fn new() -> Self {
            let base = std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
                .canonicalize()
                .expect("canonical temp base");
            let root = tempfile::Builder::new()
                .prefix("xt-tui-unit-")
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in(base)
                .expect("temp dir");
            let repo = root.path().join("repo");
            let data_home = root.path().join("data");
            std::fs::create_dir_all(&repo).expect("repo dir");
            let env_reader = |key: &str| (key == "XTRACE_DATA_HOME").then(|| data_home.clone());
            crate::commands::init(repo.clone(), "TuiUnit".to_owned(), String::new(), &env_reader)
                .expect("init project");
            let (project_id, _, _) =
                open_recording_reader(&repo, &env_reader).expect("open reader");
            let project_root = data_home.join("projects").join(project_id.to_string());
            let dir_mode =
                std::fs::metadata(&project_root).expect("project dir").permissions().mode() & 0o777;
            let db_mode = std::fs::metadata(project_root.join("metadata.sqlite3"))
                .expect("db")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(db_mode, 0o600);
            Self { _root: root, repo, data_home, project_id }
        }

        fn project_root(&self) -> PathBuf {
            self.data_home.join("projects").join(self.project_id.to_string())
        }

        fn persistence(&self) -> SqliteRecordingPersistence {
            let store = SqliteStore::open(
                &self.project_root().join("metadata.sqlite3"),
                OpenOptions::default().with_must_exist(true),
            )
            .expect("open store");
            SqliteRecordingPersistence::new(store, self.project_root())
        }

        fn facade(&self, list_limit: u32) -> Facade {
            let data_home = self.data_home.clone();
            let opener: OpenReaderFn = Box::new(move |dir| {
                let env_reader = |key: &str| (key == "XTRACE_DATA_HOME").then(|| data_home.clone());
                let (id, reader, _) = open_recording_reader(dir, &env_reader)?;
                Ok((id, reader))
            });
            Facade::open(self.repo.clone(), opener, list_limit).expect("open facade")
        }
    }

    fn make_event(
        seq: u64,
        event_id: &str,
        parent_id: &str,
        kind: RecordingEventKind,
        symbol: &str,
    ) -> AcceptedRecordingEvent<XtfEventEnvelope> {
        let payload = XtfEventEnvelope {
            recording_seq: seq,
            event: Some(RecordingEvent {
                event_id: event_id.to_owned(),
                parent_event_id: parent_id.to_owned(),
                recording_seq: seq,
                monotonic_ns: seq * 10,
                kind: kind as i32,
                symbol: symbol.to_owned(),
                ..RecordingEvent::default()
            }),
        };
        AcceptedRecordingEvent {
            recording_seq: seq,
            monotonic_ns: seq * 10,
            priority: 0,
            canonical_bytes: payload.encode_to_vec(),
            payload,
        }
    }

    fn finish_recording(
        persistence: &SqliteRecordingPersistence,
        recording_id: RecordingId,
        events: &[AcceptedRecordingEvent<XtfEventEnvelope>],
        outcome: Option<RecordingOutcome>,
    ) {
        let mut digest = blake3::Hasher::new();
        for event in events {
            let id = &event.payload.event.as_ref().expect("event").event_id;
            digest.update(id.as_bytes());
        }
        let last_seq = events.last().map_or(1, |e| e.recording_seq);
        persistence
            .finish_recording(&FinishRecording {
                recording_id,
                final_recording_seq: last_seq,
                duration_ns: Some(100),
                event_digest: digest.finalize().as_bytes().to_vec(),
                drop_counts_by_priority: BTreeMap::new(),
                unsupported_capability_codes: Vec::new(),
                capacity_dropped_events: 0,
                event_cap: STANDARD_EVENT_CAP as u64,
                response_summary: None,
                outcome,
            })
            .expect("finish recording");
    }

    #[test]
    fn facade_lists_pages_window_cursors_honesty_and_reconnects() {
        let project = TestProject::new();
        let persistence = project.persistence();
        let session = RuntimeSessionId::new();
        let rec1 = RecordingId::new();
        let rec2 = RecordingId::new();
        let rec3 = RecordingId::new();

        // Recording 1: rich honesty fields (route, outcome, limitations, gap, bindings, source/line, truncation).
        persistence
            .begin_recording(&BeginRecording {
                project_id: project.project_id,
                recording_id: rec1,
                runtime_session_id: session,
                opened_at: WallTime::from_parts(2026, 9, 29, 1, 0, 1, 0).expect("time"),
                endpoint_observation: EndpointObservationInput::default(),
                limitations: vec![LIMITATION_CAPTURE_POLICY_NOT_ARMED.to_owned()],
            })
            .expect("begin rec1");
        let canary = "PRIVATE_CANARY_UNIT_SECRET";
        let mut e_req = make_event(
            2,
            "r1-req",
            "",
            RecordingEventKind::RequestUpdate,
            "http.request GET /owners",
        );
        e_req.canonical_bytes = e_req.payload.encode_to_vec();
        let mut e_enter =
            make_event(3, "r1-enter", "", RecordingEventKind::FrameEnter, "OwnerCtrl.show");
        e_enter.payload.event.as_mut().expect("event").bindings = vec![
            ValueBinding {
                name: "secret".to_owned(),
                role: BindingRole::Argument as i32,
                name_origin: NameOrigin::Declared as i32,
                value: Some(WireValue {
                    value: Some(WireVariant::Redacted(CapturedValueRedacted {
                        rule_id: "auth-token".to_owned(),
                        shape_hint: ValueShape::String as i32,
                    })),
                }),
            },
            ValueBinding {
                name: "body".to_owned(),
                role: BindingRole::Argument as i32,
                name_origin: NameOrigin::Declared as i32,
                value: Some(WireValue {
                    value: Some(WireVariant::Truncated(CapturedValueTruncated {
                        preview: "head".to_owned(),
                        original_size_lower_bound: 900,
                        limit: 4,
                    })),
                }),
            },
            ValueBinding {
                name: "unav".to_owned(),
                role: BindingRole::Local as i32,
                name_origin: NameOrigin::Declared as i32,
                value: Some(WireValue {
                    value: Some(WireVariant::Unavailable(CapturedValueUnavailable { reason: 6 })),
                }),
            },
            ValueBinding {
                name: "drop".to_owned(),
                role: BindingRole::Local as i32,
                name_origin: NameOrigin::Declared as i32,
                value: Some(WireValue {
                    value: Some(WireVariant::Dropped(CapturedValueDropped { reason: 7 })),
                }),
            },
            ValueBinding {
                name: "ok".to_owned(),
                role: BindingRole::Argument as i32,
                name_origin: NameOrigin::Declared as i32,
                value: Some(WireValue {
                    value: Some(WireVariant::Captured(CapturedValueCaptured {
                        shape: ValueShape::Integer64 as i32,
                        preview: "42".to_owned(),
                        content_hash: blake3::hash(b"42").as_bytes().to_vec().into(),
                    })),
                }),
            },
        ];
        e_enter.canonical_bytes = e_enter.payload.encode_to_vec();
        let mut e_line = make_event(4, "r1-line", "r1-enter", RecordingEventKind::LineCursor, "");
        {
            let nested = e_line.payload.event.as_mut().expect("event");
            nested.source_binding = SourceBinding::ObservedUnattested as i32;
            nested.source = Some(SourceRange {
                path: "src/Owners.java".to_owned(),
                start_line: 17,
                end_line: 17,
                content_hash: vec![7; 32].into(),
                ..SourceRange::default()
            });
        }
        e_line.canonical_bytes = e_line.payload.encode_to_vec();
        let oversized_symbol = format!("{}_{canary}", "x".repeat(270));
        let e_trunc = make_event(
            5,
            "r1-trunc",
            "r1-enter",
            RecordingEventKind::FrameEnter,
            &oversized_symbol,
        );
        let mut e_gap = make_event(6, "r1-gap", "r1-enter", RecordingEventKind::Gap, "");
        e_gap.payload.event.as_mut().expect("event").gap = Some(GapPayload {
            reason: GapReason::LineBudget as i32,
            count: 5,
            first_recording_seq: 5,
            last_recording_seq: 5,
        });
        e_gap.canonical_bytes = e_gap.payload.encode_to_vec();
        let events1 = vec![e_req, e_enter, e_line, e_trunc, e_gap];
        persistence
            .persist_segment(&PersistRecordingSegment {
                project_id: project.project_id,
                recording_id: rec1,
                segment_ordinal: 0,
                events: events1.clone(),
            })
            .expect("segment rec1");
        finish_recording(
            &persistence,
            rec1,
            &events1,
            Some(RecordingOutcome {
                kind: OutcomeKind::Responded,
                http_status: Some(200),
                exception: None,
                thrown_from_event_id: None,
            }),
        );

        // Recording 2: 505 events to force window cursor paging.
        persistence
            .begin_recording(&BeginRecording {
                project_id: project.project_id,
                recording_id: rec2,
                runtime_session_id: session,
                opened_at: WallTime::from_parts(2026, 9, 29, 1, 0, 2, 0).expect("time"),
                endpoint_observation: EndpointObservationInput {
                    policy_id: Some("spring-orders-v1".to_owned()),
                    application_component: Some("spring-fixture".to_owned()),
                    binding_key: Some("default".to_owned()),
                    method: "POST".to_owned(),
                    route_template: "/orders".to_owned(),
                },
                limitations: Vec::new(),
            })
            .expect("begin rec2");
        let seg0: Vec<_> = (0..500_u64)
            .map(|i| {
                let seq = i + 2;
                make_event(
                    seq,
                    &format!("r2-{seq}"),
                    "",
                    RecordingEventKind::FrameEnter,
                    &format!("Scale.f{seq}"),
                )
            })
            .collect();
        let seg1: Vec<_> = (500..505_u64)
            .map(|i| {
                let seq = i + 2;
                make_event(
                    seq,
                    &format!("r2-{seq}"),
                    "",
                    RecordingEventKind::FrameEnter,
                    &format!("Scale.f{seq}"),
                )
            })
            .collect();
        persistence
            .persist_segment(&PersistRecordingSegment {
                project_id: project.project_id,
                recording_id: rec2,
                segment_ordinal: 0,
                events: seg0.clone(),
            })
            .expect("seg0");
        persistence
            .persist_segment(&PersistRecordingSegment {
                project_id: project.project_id,
                recording_id: rec2,
                segment_ordinal: 1,
                events: seg1.clone(),
            })
            .expect("seg1");
        let mut all2 = seg0;
        all2.extend(seg1);
        finish_recording(
            &persistence,
            rec2,
            &all2,
            Some(RecordingOutcome {
                kind: OutcomeKind::Responded,
                http_status: Some(201),
                exception: None,
                thrown_from_event_id: None,
            }),
        );

        let facade = project.facade(1);
        let p1 = facade.list_recordings_page(None).expect("page 1");
        assert!(p1.has_more);
        assert_eq!(p1.recordings.len(), 1);
        assert_eq!(p1.recordings[0].id, rec2.to_string());
        assert_eq!(p1.recordings[0].route.as_deref(), Some("POST /orders"));
        assert_eq!(p1.recordings[0].outcome.as_deref(), Some("responded"));

        let p2 = facade.list_recordings_page(p1.next_after.as_deref()).expect("page 2");
        assert!(!p2.has_more);
        assert_eq!(p2.recordings[0].id, rec1.to_string());
        assert_eq!(p2.recordings[0].route.as_deref(), Some("GET /owners"));

        let w1 = facade.window_page(&rec1.to_string(), None, None).expect("w1");
        assert_eq!(w1.route.as_deref(), Some("GET /owners"));
        assert_eq!(w1.outcome.as_deref(), Some("responded 200"));
        assert_eq!(w1.limitations, ["capture_policy_not_armed"]);
        assert_eq!(w1.frames[2].source_location.as_deref(), Some("src/Owners.java:17"));
        assert_eq!(w1.frames[4].gap_reason.as_deref(), Some("line_budget"));
        assert_eq!(w1.frames[4].gap_count, Some(5));
        assert!(w1.frames[3].truncated);
        assert!(w1.frames[3].field_truncations.iter().any(|t| t.contains("symbol (truncated")));
        assert!(w1.frames[1].bindings_summary.iter().any(|b| b.contains("redacted by auth-token")));
        assert!(w1.frames[1].bindings_summary.iter().any(|b| b.contains("truncated 4/900B")));
        assert!(
            w1.frames[1]
                .bindings_summary
                .iter()
                .any(|b| b.contains("unavailable: focused_capture_not_armed"))
        );
        assert!(w1.frames[1].bindings_summary.iter().any(|b| b.contains("dropped: value_budget")));
        assert!(!format!("{w1:?}").contains(canary));

        // Window cursor paging on rec2 (capped by WINDOW_LIMIT and MAX_RECORDING_EVENT_PROJECTION_BYTES).
        let bw1 = facade.window_page(&rec2.to_string(), None, None).expect("bw1");
        let page1_len = bw1.frames.len();
        assert!(
            page1_len > 0 && page1_len <= usize::try_from(WINDOW_LIMIT).unwrap() && page1_len < 505,
            "expected bounded first page, got {page1_len}"
        );
        assert_eq!(bw1.frames[0].sequence, 2);
        assert!(bw1.prev_cursor.is_none());
        let next_c = bw1.next_cursor.as_deref().expect("next cursor");
        let bw2 = facade.window_page(&rec2.to_string(), None, Some(next_c)).expect("bw2");
        assert!(!bw2.frames.is_empty());
        assert_eq!(bw2.frames[0].sequence, bw1.frames.last().expect("bw1 last").sequence + 1);
        assert_eq!(bw2.route.as_deref(), Some("POST /orders"));

        let mut total_frames = page1_len + bw2.frames.len();
        let mut last_seq = bw2.frames.last().expect("bw2 last").sequence;
        let mut cur = bw2.next_cursor.clone();
        while let Some(token) = cur {
            let next_page = facade.window_page(&rec2.to_string(), None, Some(&token)).expect("bw+");
            assert!(!next_page.frames.is_empty());
            assert_eq!(next_page.frames[0].sequence, last_seq + 1);
            total_frames += next_page.frames.len();
            last_seq = next_page.frames.last().expect("last").sequence;
            cur = next_page.next_cursor;
        }
        assert_eq!(total_frames, 505);
        assert_eq!(last_seq, 506);

        let prev_c = bw2.prev_cursor.as_deref().expect("prev cursor");
        let bw_back = facade.window_page(&rec2.to_string(), None, Some(prev_c)).expect("bw_back");
        assert_eq!(bw_back.frames.len(), page1_len);
        assert_eq!(bw_back.frames[0].sequence, 2);
        assert_eq!(
            bw_back.frames.last().expect("bw_back last").sequence + 1,
            bw2.frames[0].sequence
        );

        // Reconnect picks up newly persisted rec3.
        persistence
            .begin_recording(&BeginRecording {
                project_id: project.project_id,
                recording_id: rec3,
                runtime_session_id: session,
                opened_at: WallTime::from_parts(2026, 9, 29, 1, 0, 3, 0).expect("time"),
                endpoint_observation: EndpointObservationInput::default(),
                limitations: Vec::new(),
            })
            .expect("begin rec3");
        let ev3 = vec![make_event(
            2,
            "r3-req",
            "",
            RecordingEventKind::RequestUpdate,
            "http.request GET /vets",
        )];
        persistence
            .persist_segment(&PersistRecordingSegment {
                project_id: project.project_id,
                recording_id: rec3,
                segment_ordinal: 0,
                events: ev3.clone(),
            })
            .expect("seg rec3");
        finish_recording(&persistence, rec3, &ev3, None);

        facade.reconnect().expect("reconnect");
        let refreshed = facade.list_recordings_page(None).expect("refreshed");
        assert_eq!(refreshed.recordings[0].id, rec3.to_string());
        assert_eq!(refreshed.recordings[0].route.as_deref(), Some("GET /vets"));
    }
}
