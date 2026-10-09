//! Terminal driver around the pure core: key decoding, effect execution, redraw and (on a real
//! terminal) raw-mode setup. Standard library only: raw mode and the terminal size come from the
//! system `stty`, restored on every exit path by a guard.

use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use crate::client::ReplayClient;
use crate::model::{Effect, Key, Message, Model, NavAction, Status};
use crate::update::update;
use crate::view::render;

/// Default size when the terminal size cannot be read (plain mode, pipes).
pub const DEFAULT_SIZE: (u16, u16) = (100, 30);

/// Decodes terminal input bytes into keys. Incomplete escape sequences stay in `pending` for the
/// next call; unknown sequences and bytes are dropped, never guessed.
pub fn decode_keys(pending: &mut Vec<u8>, incoming: &[u8]) -> Vec<Key> {
    pending.extend_from_slice(incoming);
    let mut keys = Vec::new();
    let mut index = 0;
    while index < pending.len() {
        let byte = pending[index];
        if byte == 0x1b {
            match pending.get(index + 1) {
                None => break,
                Some(b'[' | b'O') => {
                    // CSI or SS3: final byte is the first one in 0x40..=0x7e after the introducer.
                    let rest = &pending[index + 2..];
                    let Some(end) = rest.iter().position(|b| (0x40..=0x7e).contains(b)) else {
                        break;
                    };
                    match rest[end] {
                        b'A' => keys.push(Key::Up),
                        b'B' => keys.push(Key::Down),
                        _ => {}
                    }
                    index += 2 + end + 1;
                }
                Some(_) => {
                    // Escape followed by another key: treat the escape as "back".
                    keys.push(Key::Back);
                    index += 1;
                }
            }
            continue;
        }
        match byte {
            b'k' => keys.push(Key::Up),
            b'j' => keys.push(Key::Down),
            b'\r' | b'\n' => keys.push(Key::Enter),
            b'b' => keys.push(Key::Back),
            b'[' => keys.push(Key::Nav(NavAction::Previous)),
            b']' => keys.push(Key::Nav(NavAction::Next)),
            b'i' => keys.push(Key::Nav(NavAction::Into)),
            b'o' => keys.push(Key::Nav(NavAction::Over)),
            b'u' => keys.push(Key::Nav(NavAction::Out)),
            b'r' => keys.push(Key::Refresh),
            b'?' => keys.push(Key::Help),
            b'q' | 0x03 | 0x04 => keys.push(Key::Quit),
            _ => {}
        }
        index += 1;
    }
    pending.drain(..index);
    keys
}

/// Runs one effect against the client and returns the message to feed back, or `None` for
/// `Quit`.
pub fn perform<C: ReplayClient>(client: &C, effect: Effect) -> Option<Message> {
    match effect {
        Effect::LoadRecordings => {
            Some(Message::RecordingsLoaded(client.list_recordings().map_err(|e| e.0)))
        }
        Effect::LoadWindow { recording_id, around_frame } => Some(Message::WindowLoaded(
            client.window(&recording_id, around_frame.as_deref()).map_err(|e| e.0),
        )),
        Effect::Navigate { recording_id, frame_id, action } => {
            let result = client.navigate(&recording_id, &frame_id, action).map_err(|e| e.0);
            Some(Message::Navigated { recording_id, from_frame: frame_id, action, result })
        }
        Effect::Quit => None,
    }
}

/// Feeds `message` through the core and settles every effect it causes. Returns the new model and
/// whether the program should quit.
pub fn step<C: ReplayClient>(client: &C, model: Model, message: Message) -> (Model, bool) {
    let (mut model, effects) = update(model, message);
    let mut pending = effects;
    let mut quit = false;
    // Bounded: every effect yields at most one message and a window request never re-requests.
    let mut budget = 32;
    while let Some(effect) = pending.pop() {
        if budget == 0 {
            break;
        }
        budget -= 1;
        match perform(client, effect) {
            Some(next) => {
                let (m, more) = update(model, next);
                model = m;
                pending.extend(more);
            }
            None => quit = true,
        }
    }
    (model, quit)
}

/// Renders once as plain text (no escape sequences), optionally with one recording open.
///
/// # Errors
///
/// Returns the safe client message when the list cannot be read or the recording is not in it.
pub fn render_plain<C: ReplayClient>(
    client: &C,
    size: (u16, u16),
    recording: Option<&str>,
) -> Result<String, String> {
    let model = Model::new(size.0, size.1, true);
    let (mut model, _) = step(client, model, Message::Key(Key::Refresh));
    if let Status::Failed(text) = &model.status {
        return Err(text.clone());
    }
    if let Some(id) = recording {
        let Some(index) = model.recordings.iter().position(|r| r.id == id) else {
            return Err("that recording is not in this project".to_owned());
        };
        model.selected_recording = index;
        let (m, _) = step(client, model, Message::Key(Key::Enter));
        model = m;
        if let Status::Failed(text) = &model.status {
            return Err(text.clone());
        }
    }
    Ok(render(&model).to_plain())
}

fn draw<W: Write>(out: &mut W, model: &Model) -> io::Result<()> {
    let grid = render(model);
    let text = grid.output(false);
    // Home, then each row followed by erase-to-end; no scroll because the last newline is dropped.
    let body = text.strip_suffix('\n').unwrap_or(&text);
    out.write_all(b"\x1b[H")?;
    for (index, row) in body.split('\n').enumerate() {
        if index > 0 {
            out.write_all(b"\r\n")?;
        }
        out.write_all(row.as_bytes())?;
        out.write_all(b"\x1b[K")?;
    }
    out.write_all(b"\x1b[J")?;
    out.flush()
}

/// The interactive loop. `input` delivers raw terminal bytes; a closed channel quits. `probe`
/// returns the current terminal size (polled because the standard library has no SIGWINCH).
///
/// # Errors
///
/// Returns the first write error.
pub fn run_loop<C: ReplayClient, W: Write>(
    client: &C,
    out: &mut W,
    input: &Receiver<Vec<u8>>,
    mut probe: impl FnMut() -> Option<(u16, u16)>,
    size: (u16, u16),
) -> io::Result<()> {
    let model = Model::new(size.0, size.1, false);
    let (mut model, mut quit) = step(client, model, Message::Key(Key::Refresh));
    draw(out, &model)?;
    let mut pending = Vec::new();
    while !quit {
        let mut dirty = false;
        match input.recv_timeout(Duration::from_millis(150)) {
            Ok(bytes) => {
                for key in decode_keys(&mut pending, &bytes) {
                    let (m, q) = step(client, model, Message::Key(key));
                    model = m;
                    quit |= q;
                    dirty = true;
                    if q {
                        break;
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if pending == [0x1b] {
                    pending.clear();
                    let (m, _) = step(client, model, Message::Key(Key::Back));
                    model = m;
                    dirty = true;
                }
                if let Some((w, h)) = probe() {
                    if (w, h) != (model.width, model.height) {
                        let (m, _) = step(client, model, Message::Resize(w, h));
                        model = m;
                        dirty = true;
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => quit = true,
        }
        if dirty && !quit {
            draw(out, &model)?;
        }
    }
    Ok(())
}

/// Restores the terminal on drop: cooked mode from the saved `stty` state, cursor, main screen.
struct TerminalGuard {
    saved: String,
}

impl TerminalGuard {
    fn enter() -> Option<Self> {
        let saved = stty(&["-g"])?;
        stty(&["-icanon", "-echo", "-isig", "-ixon", "min", "1", "time", "0"])?;
        let mut out = io::stdout();
        // Alternate screen, hidden cursor.
        out.write_all(b"\x1b[?1049h\x1b[?25l").ok()?;
        out.flush().ok()?;
        Some(Self { saved: saved.trim().to_owned() })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let mut out = io::stdout();
        let _ = out.write_all(b"\x1b[?25h\x1b[?1049l");
        let _ = out.flush();
        let _ = stty(&[self.saved.as_str()]);
    }
}

fn stty(args: &[&str]) -> Option<String> {
    let output = Command::new("stty")
        .args(args)
        .stdin(Stdio::inherit())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Terminal size as `(columns, rows)`, from the controlling terminal on stdin.
#[must_use]
pub fn terminal_size() -> Option<(u16, u16)> {
    let text = stty(&["size"])?;
    let mut parts = text.split_whitespace();
    let rows: u16 = parts.next()?.parse().ok()?;
    let cols: u16 = parts.next()?.parse().ok()?;
    (rows > 0 && cols > 0).then_some((cols, rows))
}

/// Runs the full-screen viewer on the controlling terminal.
///
/// # Errors
///
/// Fails when stdin is not a terminal or raw mode cannot be entered; the caller should suggest
/// the plain mode in that case.
pub fn run_interactive<C: ReplayClient>(client: &C) -> io::Result<()> {
    use io::IsTerminal as _;
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the interactive viewer needs a terminal; use --plain",
        ));
    }
    let size = terminal_size().unwrap_or(DEFAULT_SIZE);
    let Some(guard) = TerminalGuard::enter() else {
        return Err(io::Error::other("could not switch the terminal to raw mode"));
    };
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        let mut buf = [0_u8; 64];
        while let Ok(n) = stdin.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut out = io::stdout();
    let result = run_loop(client, &mut out, &rx, terminal_size, size);
    drop(guard);
    result
}
