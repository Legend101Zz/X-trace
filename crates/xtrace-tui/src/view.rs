//! Rendering a model to a fixed-size character grid.
//!
//! Widths are counted in `char`s; the persisted symbols this viewer shows are ASCII identifiers.
//! Wide-glyph handling is a known limitation, not hidden: nothing here claims otherwise.

use crate::model::{FrameRow, Model, NavAction, NavResult, Screen, Status};

/// Smallest supported terminal.
pub const MIN_WIDTH: u16 = 40;
/// Smallest supported terminal.
pub const MIN_HEIGHT: u16 = 8;

/// A rendered screen: exactly `height` rows of exactly `width` chars.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grid {
    rows: Vec<String>,
    selected_row: Option<usize>,
}

impl Grid {
    /// The rows, each padded to the grid width.
    #[must_use]
    pub fn rows(&self) -> &[String] {
        &self.rows
    }

    /// Plain text with trailing blanks trimmed; never contains an escape sequence.
    #[must_use]
    pub fn to_plain(&self) -> String {
        // Trailing blank rows are dropped so the text never ends in blank lines (`git diff
        // --check` flags blank lines at end of file in the stored snapshots).
        let mut rows: Vec<&str> = self.rows.iter().map(|row| row.trim_end()).collect();
        while rows.last().is_some_and(|row| row.is_empty()) {
            rows.pop();
        }
        let mut text = rows.join("\n");
        text.push('\n');
        text
    }

    /// Terminal output: reverse video marks the selected row unless `plain` is set.
    #[must_use]
    pub fn output(&self, plain: bool) -> String {
        if plain {
            return self.to_plain();
        }
        let mut text = String::new();
        for (index, row) in self.rows.iter().enumerate() {
            if self.selected_row == Some(index) {
                text.push_str("\u{1b}[7m");
                text.push_str(row);
                text.push_str("\u{1b}[0m");
            } else {
                text.push_str(row.trim_end());
            }
            text.push('\n');
        }
        text
    }
}

/// Replaces every control character (ESC, newline, CR, C1, DEL) with U+FFFD. Recorded text is
/// untrusted: it must never reach the terminal as an escape sequence or change the row count.
fn sanitize(text: &str) -> String {
    text.chars().map(|c| if c.is_control() || is_format_char(c) { '\u{fffd}' } else { c }).collect()
}

/// Invisible format characters that can reorder or hide recorded text on screen: zero-width and
/// directional marks (U+200B-200F), line/paragraph separators and embeddings/overrides
/// (U+2028-202E), directional isolates and invisible operators (U+2060-206F), the soft hyphen, Arabic letter mark,
/// Mongolian vowel separator, interlinear annotation marks (U+FFF9-FFFB), the tag block
/// (U+E0000-E007F) and the byte-order mark (U+FEFF).
/// Wide (CJK or emoji) glyphs are NOT measured: width is counted in chars, as the module doc says.
fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0000}'..='\u{e007f}'
    )
}

/// The server labels a gap event `recording_event_kind:gap`; accept that and a bare `gap`.
fn is_gap(kind: &str) -> bool {
    kind == "gap" || kind.ends_with(":gap")
}

fn fit(text: &str, width: usize) -> String {
    let clean = sanitize(text);
    let text = clean.as_str();
    let count = text.chars().count();
    if count <= width {
        let mut out = text.to_owned();
        out.extend(std::iter::repeat_n(' ', width - count));
        out
    } else if width == 0 {
        String::new()
    } else {
        let mut out: String = text.chars().take(width - 1).collect();
        out.push('~');
        out
    }
}

/// Renders the model. Pure.
#[must_use]
pub fn render(model: &Model) -> Grid {
    let width = usize::from(model.width);
    let height = usize::from(model.height);
    if model.width < MIN_WIDTH || model.height < MIN_HEIGHT {
        let mut rows = vec![fit("", width); height];
        if let Some(first) = rows.first_mut() {
            *first = fit(
                &format!("Need {MIN_WIDTH}x{MIN_HEIGHT}, have {}x{}", model.width, model.height),
                width,
            );
        }
        return Grid { rows, selected_row: None };
    }
    let mut rows: Vec<String> = Vec::with_capacity(height);
    let mut selected_row = None;
    rows.push(fit(&title(model), width));
    let footer_rows = if model.screen == Screen::Replay { 3 } else { 2 };
    let body_height = height - 1 - footer_rows;
    let body = if model.help { help_body() } else { body_lines(model, body_height) };
    let first_visible = body.offset;
    for (index, line) in body.lines.iter().enumerate().take(body_height) {
        if body.selected == Some(first_visible + index) {
            selected_row = Some(rows.len());
        }
        rows.push(fit(line, width));
    }
    while rows.len() < 1 + body_height {
        rows.push(fit("", width));
    }
    if model.screen == Screen::Replay {
        rows.push(fit(&nav_line(model), width));
    }
    rows.push(fit(&notice_line(model), width));
    rows.push(fit(&hint_line(model), width));
    Grid { rows, selected_row }
}

struct Body {
    lines: Vec<String>,
    /// Index of the first line within the full list (scroll offset).
    offset: usize,
    /// Index within the full list of the selected line.
    selected: Option<usize>,
}

fn title(model: &Model) -> String {
    match (&model.screen, &model.open_recording) {
        (Screen::Replay, Some(id)) => format!("X-trace · replay {id}"),
        _ => "X-trace · recordings".to_owned(),
    }
}

fn help_body() -> Body {
    let lines = [
        "Keys",
        "  up/down    move selection",
        "  enter      open recording",
        "  b          back to list",
        "  [ ]        previous / next frame",
        "  i o u      step into / over / out",
        "  r          refresh",
        "  ?          close this help",
        "  q          quit",
    ];
    Body { lines: lines.iter().map(|l| (*l).to_owned()).collect(), offset: 0, selected: None }
}

fn window_start(selected: usize, len: usize, height: usize) -> usize {
    if height == 0 || len <= height {
        return 0;
    }
    selected.saturating_sub(height / 2).min(len - height)
}

fn body_lines(model: &Model, height: usize) -> Body {
    match &model.status {
        Status::Loading if model.recordings.is_empty() && model.window.is_none() => {
            return Body {
                lines: vec!["Reading persisted evidence…".to_owned()],
                offset: 0,
                selected: None,
            };
        }
        Status::Failed(text) => {
            return Body {
                lines: vec![
                    "Could not load persisted evidence".to_owned(),
                    text.clone(),
                    "Press r to retry.".to_owned(),
                ],
                offset: 0,
                selected: None,
            };
        }
        _ => {}
    }
    match model.screen {
        Screen::Recordings => {
            if model.recordings.is_empty() {
                let text = if model.status == Status::Idle {
                    "Press r to load recordings."
                } else {
                    "No recordings persisted."
                };
                return Body { lines: vec![text.to_owned()], offset: 0, selected: None };
            }
            let start = window_start(model.selected_recording, model.recordings.len(), height);
            let lines = model
                .recordings
                .iter()
                .enumerate()
                .skip(start)
                .take(height)
                .map(|(index, row)| {
                    let marker = if index == model.selected_recording { '>' } else { ' ' };
                    format!("{marker} {}  {}  {} events", row.id, row.completion, row.event_count)
                })
                .collect();
            Body { lines, offset: start, selected: Some(model.selected_recording) }
        }
        Screen::Replay => {
            let Some(window) = &model.window else {
                return Body {
                    lines: vec!["Select a recording.".to_owned()],
                    offset: 0,
                    selected: None,
                };
            };
            if window.frames.is_empty() {
                return Body {
                    lines: vec![
                        "The persisted recording has no event window to display.".to_owned(),
                    ],
                    offset: 0,
                    selected: None,
                };
            }
            let start = window_start(model.selected_frame, window.frames.len(), height);
            let lines = window
                .frames
                .iter()
                .enumerate()
                .skip(start)
                .take(height)
                .map(|(index, frame)| frame_line(frame, index == model.selected_frame))
                .collect();
            Body { lines, offset: start, selected: Some(model.selected_frame) }
        }
    }
}

fn frame_line(frame: &FrameRow, selected: bool) -> String {
    let marker = if selected { '>' } else { ' ' };
    let indent = " ".repeat(frame.depth.map_or(0, |d| usize::try_from(d.min(12)).unwrap_or(0)));
    let symbol = frame.symbol.as_deref().unwrap_or("no symbol persisted");
    if is_gap(&frame.kind) {
        format!("{marker} {:>5} {indent}GAP: events were not emitted here", frame.sequence)
    } else {
        format!("{marker} {:>5} {indent}{} {symbol}", frame.sequence, frame.kind)
    }
}

fn nav_line(model: &Model) -> String {
    let Some(frame) = model.window.as_ref().and_then(|w| w.frames.get(model.selected_frame)) else {
        return "nav: no frame selected".to_owned();
    };
    let mut parts = Vec::new();
    for action in
        [NavAction::Previous, NavAction::Next, NavAction::Into, NavAction::Over, NavAction::Out]
    {
        let state = match frame.navigation.get(action as usize).and_then(Option::as_ref) {
            Some(NavResult::Target(_)) => "ok",
            Some(NavResult::Boundary(_)) => "boundary",
            Some(NavResult::Unavailable(_)) => "unavailable",
            None => "not resolved",
        };
        parts.push(format!("{} {state}", action.label()));
    }
    format!("nav: {}", parts.join(" | "))
}

fn notice_line(model: &Model) -> String {
    if !model.notice.is_empty() {
        return model.notice.clone();
    }
    match (&model.screen, &model.window) {
        (Screen::Replay, Some(window)) => {
            format!("{} frames · recording {}", window.frames.len(), window.completion)
        }
        _ => String::new(),
    }
}

fn hint_line(model: &Model) -> String {
    match model.screen {
        Screen::Recordings => {
            "up/down select · enter open · r refresh · ? help · q quit".to_owned()
        }
        Screen::Replay => {
            "up/down select · [ ] prev/next · i o u into/over/out · b back · ? help · q quit"
                .to_owned()
        }
    }
}
