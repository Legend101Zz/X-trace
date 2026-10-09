//! Pure state transition.

use crate::model::{Effect, Key, Message, Model, NavAction, NavResult, Screen, Status};

/// Applies one message. Pure: the same inputs always give the same outputs.
#[must_use]
pub fn update(mut model: Model, message: Message) -> (Model, Vec<Effect>) {
    let mut effects = Vec::new();
    match message {
        Message::Resize(width, height) => {
            model.width = width;
            model.height = height;
        }
        Message::Key(key) => key_pressed(&mut model, key, &mut effects),
        Message::RecordingsLoaded(result) => match result {
            Ok(rows) => {
                model.selected_recording =
                    model.selected_recording.min(rows.len().saturating_sub(1));
                model.recordings = rows;
                model.status = Status::Ready;
            }
            Err(text) => model.status = Status::Failed(text),
        },
        Message::WindowLoaded(result) => match result {
            // A reply for a recording that is no longer open must not replace the open one.
            Ok(window) if model.open_recording.as_deref() == Some(window.recording_id.as_str()) => {
                let keep = model
                    .window
                    .as_ref()
                    .and_then(|old| selected_frame_id(old, model.selected_frame));
                let find =
                    |id: &str| window.frames.iter().position(|f| f.frame_id.as_deref() == Some(id));
                // A window requested around a navigation target selects that target; otherwise
                // the previous selection is kept when it is still inside the new window.
                let anchored = window.anchor_frame_id.as_deref().and_then(find);
                model.selected_frame =
                    anchored.or_else(|| keep.as_deref().and_then(find)).unwrap_or(0);
                if anchored.is_some() {
                    model.notice.clear();
                }
                model.window = Some(window);
                model.status = Status::Ready;
            }
            Ok(_) => {}
            Err(text) => {
                if model.open_recording.is_some() {
                    model.status = Status::Failed(text);
                }
            }
        },
        Message::Navigated { recording_id, from_frame, action, result } => {
            let current =
                model.window.as_ref().and_then(|w| selected_frame_id(w, model.selected_frame));
            // Ignore answers for another recording or for a frame the person has since left.
            if model.open_recording.as_deref() == Some(recording_id.as_str())
                && current.as_deref() == Some(from_frame.as_str())
            {
                apply_navigation(&mut model, &recording_id, action, result, &mut effects);
            }
        }
    }
    (model, effects)
}

fn selected_frame_id(window: &crate::model::Window, index: usize) -> Option<String> {
    window.frames.get(index).and_then(|f| f.frame_id.clone())
}

fn key_pressed(model: &mut Model, key: Key, effects: &mut Vec<Effect>) {
    match key {
        Key::Quit => effects.push(Effect::Quit),
        Key::Help => model.help = !model.help,
        Key::Up | Key::Down => {
            let delta: isize = if key == Key::Up { -1 } else { 1 };
            match model.screen {
                Screen::Recordings => {
                    model.selected_recording =
                        step(model.selected_recording, model.recordings.len(), delta)
                }
                Screen::Replay => {
                    let len = model.window.as_ref().map_or(0, |w| w.frames.len());
                    model.selected_frame = step(model.selected_frame, len, delta);
                }
            }
        }
        Key::Enter => {
            if model.screen == Screen::Recordings {
                if let Some(row) = model.recordings.get(model.selected_recording) {
                    let id = row.id.clone();
                    model.screen = Screen::Replay;
                    model.open_recording = Some(id.clone());
                    model.window = None;
                    model.selected_frame = 0;
                    model.status = Status::Loading;
                    model.notice.clear();
                    effects.push(Effect::LoadWindow { recording_id: id, around_frame: None });
                }
            }
        }
        Key::Back => {
            if model.screen == Screen::Replay {
                model.screen = Screen::Recordings;
                model.open_recording = None;
                model.window = None;
                model.status = Status::Ready;
                model.notice.clear();
            }
        }
        Key::Refresh => {
            model.status = Status::Loading;
            match (&model.screen, &model.open_recording) {
                (Screen::Replay, Some(id)) => {
                    let around = model
                        .window
                        .as_ref()
                        .and_then(|w| selected_frame_id(w, model.selected_frame));
                    effects.push(Effect::LoadWindow {
                        recording_id: id.clone(),
                        around_frame: around,
                    });
                }
                _ => effects.push(Effect::LoadRecordings),
            }
        }
        Key::Nav(action) => request_navigation(model, action, effects),
    }
}

fn request_navigation(model: &mut Model, action: NavAction, effects: &mut Vec<Effect>) {
    if model.screen != Screen::Replay {
        return;
    }
    let (Some(recording_id), Some(window)) = (model.open_recording.clone(), model.window.as_ref())
    else {
        return;
    };
    let Some(frame) = window.frames.get(model.selected_frame) else { return };
    // Use the answer already embedded in the window; ask the server only when it is absent.
    let slot = frame.navigation.get(action as usize).and_then(Clone::clone);
    let Some(frame_id) = frame.frame_id.clone() else {
        model.notice = format!("{}: this event is not a navigable frame.", action.label());
        return;
    };
    match slot {
        Some(result) => apply_navigation(model, &recording_id, action, Ok(result), effects),
        None => effects.push(Effect::Navigate { recording_id, frame_id, action }),
    }
}

fn apply_navigation(
    model: &mut Model,
    recording_id: &str,
    action: NavAction,
    result: Result<NavResult, String>,
    effects: &mut Vec<Effect>,
) {
    match result {
        Ok(NavResult::Target(frame_id)) => {
            let found = model.window.as_ref().and_then(|w| {
                w.frames.iter().position(|f| f.frame_id.as_deref() == Some(frame_id.as_str()))
            });
            if let Some(index) = found {
                model.selected_frame = index;
                model.notice = format!("{}: moved to frame {frame_id}.", action.label());
            } else {
                model.notice =
                    format!("{}: loading the window around frame {frame_id}.", action.label());
                model.status = Status::Loading;
                effects.push(Effect::LoadWindow {
                    recording_id: recording_id.to_owned(),
                    around_frame: Some(frame_id),
                });
            }
        }
        Ok(NavResult::Boundary(why)) => {
            model.notice = format!(
                "{}: boundary, {}",
                action.label(),
                why.as_deref().unwrap_or("no further frame in this direction")
            )
        }
        Ok(NavResult::Unavailable(why)) => {
            model.notice = format!("{}: unavailable, {why}", action.label())
        }
        Err(text) => model.notice = format!("{}: could not be resolved ({text}).", action.label()),
    }
}

fn step(current: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }
    current.saturating_add_signed(delta).min(len - 1)
}
