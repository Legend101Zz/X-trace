//! Launch-armed capture mode read from the private `capture.json` that sits beside the bootstrap
//! artifact (CONTRACTS 10.3). The file only ever arms a session; a missing, oversized,
//! non-private, symlinked or malformed file leaves the session on the standard policy, so it can
//! never widen what an adapter is granted by accident.

use std::path::Path;

use xtrace_domain::CaptureMode;

/// File name of the optional private capture description beside the bootstrap artifact.
pub const CAPTURE_FILE_NAME: &str = "capture.json";

/// Upper bound on the file size the daemon will read.
const MAX_BYTES: u64 = 64 * 1024;

/// Reads the launch-armed mode from `capture.json` next to `bootstrap_path`.
///
/// Never fails: every problem yields [`CaptureMode::Standard`].
#[must_use]
pub fn armed_mode_beside(bootstrap_path: &Path) -> CaptureMode {
    let Some(parent) = bootstrap_path.parent() else {
        return CaptureMode::Standard;
    };
    read_armed_mode(&parent.join(CAPTURE_FILE_NAME))
}

fn read_armed_mode(path: &Path) -> CaptureMode {
    let Some(bytes) = read_private_file(path) else {
        return CaptureMode::Standard;
    };
    parse_armed_mode(&bytes)
}

/// Parses the armed mode from the document bytes (`capture_schema_version` 1 only).
#[must_use]
pub fn parse_armed_mode(bytes: &[u8]) -> CaptureMode {
    let Ok(document) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return CaptureMode::Standard;
    };
    if document.get("capture_schema_version").and_then(serde_json::Value::as_u64) != Some(1) {
        return CaptureMode::Standard;
    }
    match document.pointer("/capture/mode").and_then(serde_json::Value::as_str) {
        Some("focused") => CaptureMode::Focused,
        _ => CaptureMode::Standard,
    }
}

#[cfg(unix)]
fn read_private_file(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;

    // symlink_metadata plus the same-inode check below keep a planted symlink from
    // redirecting the read.
    let link = std::fs::symlink_metadata(path).ok()?;
    if !link.file_type().is_file() {
        return None;
    }
    let mut file = std::fs::OpenOptions::new().read(true).open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_BYTES || meta.mode() & 0o077 != 0 {
        return None;
    }
    if meta.ino() != link.ino() || meta.dev() != link.dev() {
        return None;
    }
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).ok()?);
    file.by_ref().take(MAX_BYTES).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

#[cfg(not(unix))]
fn read_private_file(_path: &Path) -> Option<Vec<u8>> {
    None
}

#[cfg(all(test, unix))]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "test fixtures")]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    const FOCUSED: &str = r#"{"capture_schema_version":1,"capture":{"mode":"focused"}}"#;

    fn write(dir: &Path, body: &str, mode: u32) {
        let file = dir.join(CAPTURE_FILE_NAME);
        std::fs::write(&file, body).expect("write");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    fn bootstrap_in(dir: &Path) -> std::path::PathBuf {
        dir.join("bootstrap.json")
    }

    #[test]
    fn focused_private_file_arms_focused() {
        let dir = tempfile::tempdir().expect("dir");
        write(dir.path(), FOCUSED, 0o600);
        assert_eq!(armed_mode_beside(&bootstrap_in(dir.path())), CaptureMode::Focused);
    }

    #[test]
    fn absent_file_is_standard() {
        let dir = tempfile::tempdir().expect("dir");
        assert_eq!(armed_mode_beside(&bootstrap_in(dir.path())), CaptureMode::Standard);
    }

    #[test]
    fn group_readable_file_is_ignored() {
        let dir = tempfile::tempdir().expect("dir");
        write(dir.path(), FOCUSED, 0o640);
        assert_eq!(armed_mode_beside(&bootstrap_in(dir.path())), CaptureMode::Standard);
    }

    #[test]
    fn symlinked_file_is_ignored() {
        let dir = tempfile::tempdir().expect("dir");
        let target = dir.path().join("real.json");
        std::fs::write(&target, FOCUSED).expect("write");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        std::os::unix::fs::symlink(&target, dir.path().join(CAPTURE_FILE_NAME)).expect("link");
        assert_eq!(armed_mode_beside(&bootstrap_in(dir.path())), CaptureMode::Standard);
    }

    #[test]
    fn malformed_unknown_version_and_standard_modes_stay_standard() {
        assert_eq!(parse_armed_mode(b"{"), CaptureMode::Standard);
        assert_eq!(
            parse_armed_mode(br#"{"capture_schema_version":2,"capture":{"mode":"focused"}}"#),
            CaptureMode::Standard
        );
        assert_eq!(
            parse_armed_mode(br#"{"capture_schema_version":1,"capture":{"mode":"standard"}}"#),
            CaptureMode::Standard
        );
        assert_eq!(parse_armed_mode(br#"{"capture_schema_version":1}"#), CaptureMode::Standard);
        assert_eq!(
            parse_armed_mode(br#"{"capture_schema_version":1,"capture":{"mode":"FOCUSED"}}"#),
            CaptureMode::Standard
        );
    }

    #[test]
    fn unknown_fields_are_ignored() {
        assert_eq!(
            parse_armed_mode(
                br#"{"capture_schema_version":1,"future":{"x":1},"capture":{"mode":"focused","y":2}}"#
            ),
            CaptureMode::Focused
        );
    }
}
