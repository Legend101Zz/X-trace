//! Model, messages and effects.

/// Which screen is showing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    /// Recording list.
    Recordings,
    /// Frames of one recording.
    Replay,
}

/// Load status of the current screen's data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Nothing requested yet.
    Idle,
    /// A request is in flight.
    Loading,
    /// Data is shown.
    Ready,
    /// The last request failed; the text is user-safe.
    Failed(String),
}

/// One recording in the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordingRow {
    /// Recording id.
    pub id: String,
    /// `complete`, `partial`, `invalid`, ...
    pub completion: String,
    /// Persisted event count.
    pub event_count: u64,
}

/// A navigation step resolved by the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NavAction {
    /// Previous frame.
    Previous,
    /// Next frame.
    Next,
    /// Step into.
    Into,
    /// Step over.
    Over,
    /// Step out.
    Out,
}

impl NavAction {
    /// Display label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Previous => "previous",
            Self::Next => "next",
            Self::Into => "into",
            Self::Over => "over",
            Self::Out => "out",
        }
    }
}

/// Server answer for a navigation step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NavResult {
    /// Move to this frame.
    Target(String),
    /// No further frame. The wire carries no reason, so the text is optional; the update falls
    /// back to a neutral core-owned sentence.
    Boundary(Option<String>),
    /// Not resolvable; the text says why.
    Unavailable(String),
}

/// One frame row in a window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameRow {
    /// Frame id, absent for non-frame events.
    pub frame_id: Option<String>,
    /// Event sequence.
    pub sequence: u64,
    /// Event kind, passed verbatim from the server label (for example
    /// `recording_event_kind:gap`); never normalised by the client adapter.
    pub kind: String,
    /// Symbol, when persisted.
    pub symbol: Option<String>,
    /// Call depth, when indexed.
    pub depth: Option<u32>,
    /// Server-resolved navigation for this frame.
    pub navigation: [Option<NavResult>; 5],
}

/// A window of frames.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    /// Recording the window belongs to.
    pub recording_id: String,
    /// Frames in sequence order.
    pub frames: Vec<FrameRow>,
    /// Completion of the recording.
    pub completion: String,
    /// Frame the window was centred on when it was requested around one.
    pub anchor_frame_id: Option<String>,
}

/// Keys the core understands. The driver maps terminal events onto these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// Move selection up.
    Up,
    /// Move selection down.
    Down,
    /// Open the selected recording.
    Enter,
    /// Back to the list.
    Back,
    /// Step navigation keys: `[` previous, `]` next, `i` into, `o` over, `u` out.
    Nav(NavAction),
    /// Refresh the current screen.
    Refresh,
    /// Toggle help.
    Help,
    /// Quit.
    Quit,
}

/// Inputs to `update`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// A key press.
    Key(Key),
    /// The terminal was resized.
    Resize(u16, u16),
    /// The recording list arrived.
    RecordingsLoaded(Result<Vec<RecordingRow>, String>),
    /// A window arrived. Replies for a recording that is no longer open are ignored.
    WindowLoaded(Result<Window, String>),
    /// A navigation step was resolved for `from_frame` in `recording_id`.
    Navigated {
        /// Recording the step was asked for.
        recording_id: String,
        /// Frame the step started from.
        from_frame: String,
        /// The step.
        action: NavAction,
        /// The answer.
        result: Result<NavResult, String>,
    },
}

/// Work the caller must perform; results come back as messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// List recordings.
    LoadRecordings,
    /// Read a window.
    LoadWindow {
        /// Recording to read.
        recording_id: String,
        /// Centre the window on this frame.
        around_frame: Option<String>,
    },
    /// Ask the server for a navigation step.
    Navigate {
        /// Recording.
        recording_id: String,
        /// Starting frame.
        frame_id: String,
        /// Step.
        action: NavAction,
    },
    /// Leave the program.
    Quit,
}

/// Whole TUI state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    /// Current screen.
    pub screen: Screen,
    /// Terminal width in columns.
    pub width: u16,
    /// Terminal height in rows.
    pub height: u16,
    /// Plain mode: no escape sequences are ever produced.
    pub plain: bool,
    /// Data status of the current screen.
    pub status: Status,
    /// Recording list.
    pub recordings: Vec<RecordingRow>,
    /// Selected row in the list.
    pub selected_recording: usize,
    /// Open recording id.
    pub open_recording: Option<String>,
    /// Loaded window.
    pub window: Option<Window>,
    /// Selected frame row.
    pub selected_frame: usize,
    /// Latest line for the status bar (what just happened or why a step is unavailable).
    pub notice: String,
    /// Help overlay visible.
    pub help: bool,
}

impl Model {
    /// A fresh model for a terminal of the given size.
    #[must_use]
    pub fn new(width: u16, height: u16, plain: bool) -> Self {
        Self {
            screen: Screen::Recordings,
            width,
            height,
            plain,
            status: Status::Idle,
            recordings: Vec::new(),
            selected_recording: 0,
            open_recording: None,
            window: None,
            selected_frame: 0,
            notice: String::new(),
            help: false,
        }
    }
}
