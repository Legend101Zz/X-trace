//! The seam between the TUI core and the application facade.

use crate::model::{NavAction, NavResult, RecordingRow, RecordingsPage, Window};

/// A failure reading evidence. The message is safe to show: no server detail, no request id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientError(pub String);

/// Reads persisted recordings. Implemented over the application facade by the binary and by
/// fakes in tests. All methods are read-only.
pub trait ReplayClient {
    /// Lists recordings, newest first.
    fn list_recordings(&self) -> Result<Vec<RecordingRow>, ClientError>;

    /// Lists one bounded page of recordings after the optional exclusive recording-id cursor.
    fn list_recordings_page(&self, after: Option<&str>) -> Result<RecordingsPage, ClientError> {
        if after.is_some() {
            return Err(ClientError("recording list paging is unavailable".to_owned()));
        }
        Ok(RecordingsPage {
            recordings: self.list_recordings()?,
            next_after: None,
            has_more: false,
        })
    }

    /// Reads an event window, optionally centred on `around_frame`.
    fn window(&self, recording_id: &str, around_frame: Option<&str>)
    -> Result<Window, ClientError>;

    /// Reads an event window using an opaque `cursor` or centred on `around_frame`.
    fn window_page(
        &self,
        recording_id: &str,
        around_frame: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<Window, ClientError> {
        if cursor.is_some() {
            return Err(ClientError("window cursor paging is unavailable".to_owned()));
        }
        self.window(recording_id, around_frame)
    }

    /// Resolves one navigation action from a frame; the server owns the semantics.
    fn navigate(
        &self,
        recording_id: &str,
        frame_id: &str,
        action: NavAction,
    ) -> Result<NavResult, ClientError>;

    /// Re-opens / reconnects the underlying reader after a store or daemon restart.
    fn reconnect(&self) -> Result<(), ClientError> {
        Ok(())
    }
}

/// Alias matching the replay-backend terminology.
pub use ReplayClient as ReplayBackend;
