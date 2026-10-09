//! Snapshot and behaviour tests for the pure TUI core.

use std::path::PathBuf;

use xtrace_tui::{
    render, update, ClientError, Effect, FrameRow, Key, Message, Model, NavAction, NavResult, RecordingRow, ReplayClient, Screen, Status, Window,
};

fn nav(prev: Option<NavResult>, next: Option<NavResult>, into: Option<NavResult>, over: Option<NavResult>, out: Option<NavResult>) -> [Option<NavResult>; 5] {
    [prev, next, into, over, out]
}

fn frame(n: u64) -> FrameRow {
    let id = format!("f{n}");
    let prev = if n == 1 { NavResult::Boundary("this is the first frame.".into()) } else { NavResult::Target(format!("f{}", n - 1)) };
    FrameRow {
        frame_id: Some(id),
        sequence: n,
        kind: if n % 9 == 0 { "gap".into() } else { "method".into() },
        symbol: if n % 9 == 0 { None } else { Some(format!("com.example.Service{n}.call")) },
        depth: Some(u32::try_from(n % 4).unwrap_or(0)),
        navigation: nav(
            Some(prev),
            Some(NavResult::Target(format!("f{}", n + 1))),
            Some(NavResult::Target(format!("f{}", n + 1))),
            Some(NavResult::Unavailable("the recording is partial and evidence ends here.".into())),
            Some(NavResult::Boundary("this frame is at the top level.".into())),
        ),
    }
}

fn window(id: &str, count: u64) -> Window {
    Window { recording_id: id.into(), frames: (1..=count).map(frame).collect(), completion: "partial".into() }
}

fn recordings() -> Vec<RecordingRow> {
    vec![
        RecordingRow { id: "018f0000-0000-7000-8000-000000000011".into(), completion: "complete".into(), event_count: 120 },
        RecordingRow { id: "018f0000-0000-7000-8000-000000000012".into(), completion: "partial".into(), event_count: 7 },
    ]
}

fn open_replay(width: u16, height: u16, plain: bool) -> Model {
    let model = Model::new(width, height, plain);
    let (model, _) = update(model, Message::RecordingsLoaded(Ok(recordings())));
    let (model, effects) = update(model, Message::Key(Key::Enter));
    assert_eq!(effects, vec![Effect::LoadWindow { recording_id: "018f0000-0000-7000-8000-000000000011".into(), around_frame: None }]);
    let (model, _) = update(model, Message::WindowLoaded(Ok(window("018f0000-0000-7000-8000-000000000011", 30))));
    model
}

fn assert_snapshot(name: &str, actual: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots").join(format!("{name}.txt"));
    let Ok(expected) = std::fs::read_to_string(&path) else {
        // First run writes the file and fails, so a missing snapshot can never pass silently.
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, actual).expect("write snapshot");
        panic!("snapshot {name} did not exist; it was written, review it and rerun");
    };
    assert_eq!(expected, actual, "snapshot {name} differs (delete the file to regenerate after review)");
}

fn assert_fits(model: &Model) {
    let grid = render(model);
    assert_eq!(grid.rows().len(), usize::from(model.height));
    for row in grid.rows() {
        assert_eq!(row.chars().count(), usize::from(model.width), "row not padded to width: {row:?}");
    }
}

#[test]
fn tui_snapshot_80x24() {
    let mut model = open_replay(80, 24, true);
    for _ in 0..8 {
        model = update(model, Message::Key(Key::Down)).0;
    }
    assert_fits(&model);
    assert_snapshot("replay_80x24", &render(&model).to_plain());
}

#[test]
fn tui_snapshot_120x40() {
    let model = open_replay(120, 40, true);
    assert_fits(&model);
    assert_snapshot("replay_120x40", &render(&model).to_plain());
}

#[test]
fn tui_snapshot_200x60() {
    let (model, _) = update(Model::new(200, 60, true), Message::RecordingsLoaded(Ok(recordings())));
    assert_fits(&model);
    assert_snapshot("recordings_200x60", &render(&model).to_plain());
}

#[test]
fn tui_snapshot_too_small() {
    let model = Model::new(30, 6, true);
    assert_fits(&model);
    assert_snapshot("too_small_30x6", &render(&model).to_plain());
}

#[test]
fn tui_plain_mode_emits_no_escape_sequences() {
    let model = open_replay(80, 24, true);
    let output = render(&model).output(model.plain);
    assert!(!output.contains('\u{1b}'));
    // The styled output marks the selection, and only when asked.
    let styled = render(&model).output(false);
    assert!(styled.contains("\u{1b}[7m") && styled.contains("\u{1b}[0m"));
}

#[test]
fn resize_rerenders_at_every_supported_size() {
    let mut model = open_replay(80, 24, true);
    for (w, h) in [(40, 8), (80, 24), (120, 40), (200, 60), (41, 9), (39, 30)] {
        model = update(model, Message::Resize(w, h)).0;
        assert_fits(&model);
    }
}

#[test]
fn navigation_uses_embedded_result_and_selects_the_target() {
    let model = open_replay(80, 24, true);
    let (model, effects) = update(model, Message::Key(Key::Nav(NavAction::Next)));
    assert!(effects.is_empty());
    assert_eq!(model.selected_frame, 1);
    assert!(model.notice.contains("moved to frame f2"));
}

#[test]
fn navigation_boundary_and_unavailable_state_why() {
    let model = open_replay(80, 24, true);
    let (model, _) = update(model, Message::Key(Key::Nav(NavAction::Previous)));
    assert_eq!(model.selected_frame, 0);
    assert!(model.notice.contains("boundary, this is the first frame."));
    let (model, _) = update(model, Message::Key(Key::Nav(NavAction::Over)));
    assert!(model.notice.contains("unavailable, the recording is partial"));
    assert!(render(&model).to_plain().contains("over unavailable"));
}

#[test]
fn navigation_target_outside_window_requests_that_window() {
    let mut model = open_replay(80, 24, true);
    model.window.as_mut().expect("window").frames[0].navigation[1] = Some(NavResult::Target("far".into()));
    let (model, effects) = update(model, Message::Key(Key::Nav(NavAction::Next)));
    assert_eq!(effects, vec![Effect::LoadWindow { recording_id: "018f0000-0000-7000-8000-000000000011".into(), around_frame: Some("far".into()) }]);
    assert_eq!(model.status, Status::Loading);
}

#[test]
fn stale_window_for_another_recording_is_ignored() {
    let model = open_replay(80, 24, true);
    let (model, _) = update(model, Message::WindowLoaded(Ok(window("some-other-recording", 3))));
    assert_eq!(model.window.as_ref().map(|w| w.frames.len()), Some(30));
}

#[test]
fn stale_navigation_answer_for_a_frame_left_behind_is_ignored() {
    let model = open_replay(80, 24, true);
    let (model, _) = update(model, Message::Key(Key::Down));
    let (model, _) = update(model, Message::Navigated {
        recording_id: "018f0000-0000-7000-8000-000000000011".into(),
        from_frame: "f1".into(),
        action: NavAction::Next,
        result: Ok(NavResult::Target("f2".into())),
    });
    assert_eq!(model.selected_frame, 1);
    assert!(model.notice.is_empty());
}

#[test]
fn selection_clamps_and_back_returns_to_the_list() {
    let model = open_replay(80, 24, true);
    let (model, _) = update(model, Message::Key(Key::Up));
    assert_eq!(model.selected_frame, 0);
    let (model, _) = update(model, Message::Key(Key::Back));
    assert_eq!(model.screen, Screen::Recordings);
    assert!(model.window.is_none());
}

#[test]
fn failure_shows_safe_text_and_refresh_retries() {
    let (model, _) = update(Model::new(80, 24, true), Message::RecordingsLoaded(Err("Request failed with status 500.".into())));
    let text = render(&model).to_plain();
    assert!(text.contains("Could not load persisted evidence") && text.contains("Request failed with status 500."));
    let (_, effects) = update(model, Message::Key(Key::Refresh));
    assert_eq!(effects, vec![Effect::LoadRecordings]);
}

#[test]
fn quit_emits_quit_effect_and_update_is_pure() {
    let model = open_replay(80, 24, true);
    let first = update(model.clone(), Message::Key(Key::Quit));
    let second = update(model, Message::Key(Key::Quit));
    assert_eq!(first, second);
    assert_eq!(first.1, vec![Effect::Quit]);
}

struct Fake;
impl ReplayClient for Fake {
    fn list_recordings(&self) -> Result<Vec<RecordingRow>, ClientError> {
        Ok(recordings())
    }
    fn window(&self, id: &str, _around: Option<&str>) -> Result<Window, ClientError> {
        Ok(window(id, 3))
    }
    fn navigate(&self, _id: &str, _frame: &str, _action: NavAction) -> Result<NavResult, ClientError> {
        Err(ClientError("not needed".into()))
    }
}

#[test]
fn client_trait_drives_the_loop_without_a_terminal() {
    let client = Fake;
    let mut model = Model::new(80, 24, true);
    let mut pending = vec![Effect::LoadRecordings];
    while let Some(effect) = pending.pop() {
        let message = match effect {
            Effect::LoadRecordings => Message::RecordingsLoaded(client.list_recordings().map_err(|e| e.0)),
            Effect::LoadWindow { recording_id, around_frame } => Message::WindowLoaded(client.window(&recording_id, around_frame.as_deref()).map_err(|e| e.0)),
            Effect::Navigate { .. } | Effect::Quit => continue,
        };
        let (next, effects) = update(model, message);
        model = next;
        pending.extend(effects);
    }
    let (model, effects) = update(model, Message::Key(Key::Enter));
    assert_eq!(effects.len(), 1);
    assert_eq!(model.screen, Screen::Replay);
}
