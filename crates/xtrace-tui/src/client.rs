//! The seam between the TUI core and the application facade.

use crate::model::{NavAction, NavResult, RecordingRow, Window};

/// A failure reading evidence. The message is safe to show: no server detail, no request id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientError(pub String);

/// Reads persisted recordings. Implemented over the application facade by the binary and by
/// fakes in tests. All methods are read-only.
pub trait ReplayClient {
    /// Lists recordings, newest first.
    fn list_recordings(&self) -> Result<Vec<RecordingRow>, ClientError>;
    /// Reads an event window, optionally centred on `around_frame`.
    fn window(&self, recording_id: &str, around_frame: Option<&str>)
    -> Result<Window, ClientError>;
    /// Resolves one navigation action from a frame; the server owns the semantics.
    fn navigate(
        &self,
        recording_id: &str,
        frame_id: &str,
        action: NavAction,
    ) -> Result<NavResult, ClientError>;
}
