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
    let detail_headers = if model.help || matches!(model.status, Status::Failed(_)) {
        Vec::new()
    } else {
        replay_headers(model, body_height.saturating_sub(1))
    };
    let content_height = body_height.saturating_sub(detail_headers.len());
    let body = if model.help { help_body() } else { body_lines(model, content_height) };
    for header in detail_headers {
        rows.push(fit(&header, width));
    }
    let first_visible = body.offset;
    for (index, line) in body.lines.iter().enumerate().take(content_height) {
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
        (Screen::Replay, Some(id)) => {
            if let Some(route) = model.window.as_ref().and_then(|w| w.route.as_deref()) {
                format!("X-trace · replay {id} · {route}")
            } else {
                format!("X-trace · replay {id}")
            }
        }
        _ => "X-trace · recordings".to_owned(),
    }
}

fn replay_headers(model: &Model, max_lines: usize) -> Vec<String> {
    if model.screen != Screen::Replay || max_lines == 0 {
        return Vec::new();
    }
    let Some(window) = &model.window else {
        return Vec::new();
    };
    let mut headers = Vec::new();
    if window.route.is_some() || window.outcome.is_some() {
        let route = window.route.as_deref().unwrap_or("unobserved");
        let outcome = window.outcome.as_deref().unwrap_or("none");
        headers.push(format!("route: {route} · outcome: {outcome}"));
    }
    if !window.limitations.is_empty() && headers.len() < max_lines {
        headers.push(format!("limitations: {}", window.limitations.join(", ")));
    }
    headers
}

fn help_body() -> Body {
    let lines = [
        "Keys",
        "  up/down    move selection",
        "  enter      open recording",
        "  b          back to list",
        "  [ ]        previous / next frame",
        "  i o u      step into / over / out",
        "  n / p      next / previous page",
        "  r / R      refresh / reconnect store",
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
                    "Press r to retry or R to reconnect.".to_owned(),
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
                    let mut line = format!(
                        "{marker} {}  {}  {} events",
                        row.id, row.completion, row.event_count
                    );
                    if let Some(route) = &row.route {
                        line.push_str("  ");
                        line.push_str(route);
                    }
                    if let Some(outcome) = &row.outcome {
                        line.push_str("  ");
                        line.push_str(outcome);
                    }
                    line
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
            let mut all_lines = Vec::new();
            let mut selected_line_index = 0;
            for (index, frame) in window.frames.iter().enumerate() {
                if index == model.selected_frame {
                    selected_line_index = all_lines.len();
                }
                let indent =
                    " ".repeat(frame.depth.map_or(0, |d| usize::try_from(d.min(12)).unwrap_or(0)));
                let inline_source = frame
                    .source_location
                    .as_deref()
                    .filter(|loc| !is_gap(&frame.kind) && can_inline_source(frame, &indent, loc));
                all_lines.push(frame_line(
                    frame,
                    index == model.selected_frame,
                    &indent,
                    inline_source,
                ));
                if let Some(loc) = frame.source_location.as_deref() {
                    if inline_source.is_none() && !is_gap(&frame.kind) {
                        all_lines.push(format!("      {indent}source: {loc}"));
                    }
                }
                for binding in &frame.bindings_summary {
                    all_lines.push(format!("      {indent}binding: {binding}"));
                }
                if !frame.field_truncations.is_empty() {
                    all_lines.push(format!(
                        "      {indent}truncated fields: {}",
                        frame.field_truncations.join(", ")
                    ));
                }
            }
            let start = window_start(selected_line_index, all_lines.len(), height);
            let lines = all_lines.into_iter().skip(start).take(height).collect();
            Body { lines, offset: start, selected: Some(selected_line_index) }
        }
    }
}

fn can_inline_source(frame: &FrameRow, indent: &str, loc: &str) -> bool {
    let symbol_len = frame.symbol.as_deref().unwrap_or("no symbol persisted").chars().count();
    let trunc_len = if frame.truncated { 12 } else { 0 };
    // `> {:>5} {indent}{kind} {symbol} @ {loc}`
    8 + indent.len()
        + frame.kind.chars().count()
        + 1
        + symbol_len
        + 3
        + loc.chars().count()
        + trunc_len
        <= 78
}

fn frame_line(
    frame: &FrameRow,
    selected: bool,
    indent: &str,
    inline_source: Option<&str>,
) -> String {
    let marker = if selected { '>' } else { ' ' };
    let symbol = frame.symbol.as_deref().unwrap_or("no symbol persisted");
    if is_gap(&frame.kind) {
        match (&frame.gap_reason, frame.gap_count) {
            (Some(reason), Some(count)) => {
                format!("{marker} {:>5} {indent}GAP: {reason} ({count} suppressed)", frame.sequence)
            }
            (Some(reason), None) => {
                format!("{marker} {:>5} {indent}GAP: {reason}", frame.sequence)
            }
            (None, Some(count)) => {
                format!(
                    "{marker} {:>5} {indent}GAP: events were not emitted here ({count} suppressed)",
                    frame.sequence
                )
            }
            (None, None) => {
                format!("{marker} {:>5} {indent}GAP: events were not emitted here", frame.sequence)
            }
        }
    } else {
        let mut line = format!("{marker} {:>5} {indent}{} {symbol}", frame.sequence, frame.kind);
        if let Some(loc) = inline_source {
            line.push_str(" @ ");
            line.push_str(loc);
        }
        if frame.truncated {
            line.push_str(" [truncated]");
        }
        line
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
        if model.screen == Screen::Recordings && model.list_has_more {
            return format!("{} · truncated: more recordings exist (n next)", model.notice);
        }
        return model.notice.clone();
    }
    match (&model.screen, &model.window) {
        (Screen::Recordings, _) => {
            let page_num = model.list_history.len() + 1;
            match (model.list_has_more, !model.list_history.is_empty()) {
                (true, true) => format!(
                    "{} recordings shown · page {page_num} · truncated: more recordings exist (p prev / n next)",
                    model.recordings.len()
                ),
                (true, false) => format!(
                    "{} recordings shown · truncated: more recordings exist (press n for next page)",
                    model.recordings.len()
                ),
                (false, true) => format!(
                    "{} recordings shown · page {page_num} (press p for previous page)",
                    model.recordings.len()
                ),
                (false, false) => String::new(),
            }
        }
        (Screen::Replay, Some(window)) => {
            let base = format!("{} frames · recording {}", window.frames.len(), window.completion);
            match (window.prev_cursor.is_some(), window.next_cursor.is_some()) {
                (true, true) => format!("{base} · page: p prev / n next"),
                (true, false) => format!("{base} · page: p prev"),
                (false, true) => format!("{base} · page: n next"),
                (false, false) => base,
            }
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
