use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// Publishes a script in a test's private directory without opening it for writing here.
pub fn write_executable(path: &Path, script: &str) {
    let staging = path.with_extension("staging");
    // Only this child opens the executable inode for writing. Other test threads can fork
    // freely: the parent holds only a pipe, so their children cannot inherit that descriptor.
    // Replacing the shell with cat leaves no descendants holding the file after wait returns.
    let mut writer = Command::new("/bin/sh")
        .args(["-c", "exec /bin/cat > \"$1\"", "xtrace-test-writer"])
        .arg(&staging)
        .stdin(Stdio::piped())
        .spawn()
        .expect("start script writer");
    let written = writer.stdin.take().expect("script writer stdin").write_all(script.as_bytes());
    let status = writer.wait().expect("wait for script writer");
    written.expect("send script to writer");
    assert!(status.success(), "script writer failed: {status}");
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o755)).expect("chmod script");
    fs::rename(&staging, path).expect("publish script");
}
