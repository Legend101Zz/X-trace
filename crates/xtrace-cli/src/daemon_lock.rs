//! Project-scoped lock and private runtime-artifact directory for `xtrace daemon`.

#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use xtrace_domain::RuntimeSessionId;

use crate::error::CliError;

const DAEMON_DIRECTORY: &str = ".daemon";
const SESSION_DIRECTORY: &str = "sessions";
const LOCK_FILENAME: &str = "project.lock";
const BOOTSTRAP_FILENAME: &str = "bootstrap.json";
const TEMP_BOOTSTRAP_PREFIX: &str = ".bootstrap.json.tmp-";

/// Holds the advisory lock for the lifetime of a project daemon.
pub(crate) struct ProjectDaemonLock {
    _file: File,
}

/// Owns one session's private runtime directory and removes it on drop.
pub(crate) struct RuntimeDirectory {
    path: PathBuf,
    sessions_root: PathBuf,
    active: bool,
}

impl RuntimeDirectory {
    /// Creates a unique private session directory after cleaning stale
    /// directories while the caller holds the project lock.
    pub(crate) fn create(
        project_data_root: &Path,
        runtime_session_id: RuntimeSessionId,
    ) -> Result<Self, CliError> {
        let daemon_root = ensure_private_directory(&project_data_root.join(DAEMON_DIRECTORY))?;
        let sessions_root = ensure_private_directory(&daemon_root.join(SESSION_DIRECTORY))?;
        clean_stale_sessions(&sessions_root)?;

        let path = sessions_root.join(runtime_session_id.to_string());
        fs::create_dir(&path).map_err(|_| {
            CliError::StoreUnavailable("create daemon runtime directory failed".to_string())
        })?;
        set_directory_owner_only(&path)?;
        verify_child_directory(&sessions_root, &path)?;
        Ok(Self { path, sessions_root, active: true })
    }

    /// Returns the unique session directory.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Removes only the known bootstrap files and the owned session directory.
    pub(crate) fn cleanup(&mut self) -> Result<(), CliError> {
        if !self.active {
            return Ok(());
        }
        remove_session_directory(&self.sessions_root, &self.path)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for RuntimeDirectory {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            tracing::warn!(
                code = "XTR-CLI-DAEMON-CLEANUP",
                kind = ?error.exit_code(),
                "could not remove daemon runtime artifacts"
            );
        }
    }
}

/// Acquires the project lock and rejects a second daemon without waiting.
///
/// This lock coordinates cooperating daemon processes. A hostile process
/// running as the same OS user can still race namespace changes between the
/// descriptor/path identity checks; the advisory lock is not a same-UID
/// security boundary.
pub(crate) fn acquire_project_lock(
    project_data_root: &Path,
) -> Result<ProjectDaemonLock, CliError> {
    let daemon_root = ensure_private_directory(&project_data_root.join(DAEMON_DIRECTORY))?;
    let lock_path = daemon_root.join(LOCK_FILENAME);
    let file = open_lock_file(&lock_path)?;
    verify_lock_identity(&file, &lock_path)?;
    let metadata = file.metadata().map_err(|_| {
        CliError::StoreUnavailable("inspect project daemon lock failed".to_string())
    })?;
    if !metadata.is_file() || metadata.len() != 0 {
        return Err(CliError::StoreCorrupted("invalid project daemon lock file".to_string()));
    }
    set_file_owner_only(&file)?;
    verify_lock_identity(&file, &lock_path)?;
    let lock_result = fs4::FileExt::try_lock(&file);
    verify_lock_identity(&file, &lock_path)?;
    match lock_result {
        Ok(()) => Ok(ProjectDaemonLock { _file: file }),
        Err(fs4::TryLockError::WouldBlock) => Err(CliError::DaemonAlreadyRunning),
        Err(fs4::TryLockError::Error(_)) => {
            Err(CliError::StoreUnavailable("acquire project daemon lock failed".to_string()))
        }
    }
}

#[cfg(unix)]
fn verify_lock_identity(file: &File, path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt as _;

    let descriptor = file.metadata().map_err(|_| {
        CliError::StoreUnavailable("inspect project daemon lock descriptor failed".to_string())
    })?;
    let named = fs::symlink_metadata(path).map_err(|_| {
        CliError::StoreUnavailable("inspect project daemon lock path failed".to_string())
    })?;
    if !descriptor.is_file()
        || named.file_type().is_symlink()
        || !named.is_file()
        || descriptor.nlink() != 1
        || named.nlink() != 1
        || descriptor.dev() != named.dev()
        || descriptor.ino() != named.ino()
    {
        return Err(CliError::StoreCorrupted(
            "project daemon lock path is linked or changed".to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_lock_identity(_file: &File, _path: &Path) -> Result<(), CliError> {
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<PathBuf, CliError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CliError::StoreCorrupted(
                    "daemon runtime path is not a real directory".to_string(),
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| {
                CliError::StoreUnavailable("create daemon runtime directory failed".to_string())
            })?;
        }
        Err(_) => {
            return Err(CliError::StoreUnavailable(
                "inspect daemon runtime directory failed".to_string(),
            ));
        }
    }
    set_directory_owner_only(path)?;
    fs::canonicalize(path).map_err(|_| {
        CliError::StoreUnavailable("resolve daemon runtime directory failed".to_string())
    })
}

fn verify_child_directory(parent: &Path, child: &Path) -> Result<(), CliError> {
    let parent = fs::canonicalize(parent).map_err(|_| {
        CliError::StoreUnavailable("resolve daemon runtime root failed".to_string())
    })?;
    let metadata = fs::symlink_metadata(child).map_err(|_| {
        CliError::StoreUnavailable("inspect daemon session path failed".to_string())
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::StoreCorrupted("unsafe daemon session path".to_string()));
    }
    let child = fs::canonicalize(child).map_err(|_| {
        CliError::StoreUnavailable("resolve daemon session path failed".to_string())
    })?;
    if child == parent || !child.starts_with(parent) {
        return Err(CliError::StoreCorrupted("daemon session path escaped its root".to_string()));
    }
    Ok(())
}

fn clean_stale_sessions(sessions_root: &Path) -> Result<(), CliError> {
    let entries = fs::read_dir(sessions_root).map_err(|_| {
        CliError::StoreUnavailable("list daemon runtime directories failed".to_string())
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            CliError::StoreUnavailable("read daemon runtime entry failed".to_string())
        })?;
        let path = entry.path();
        verify_child_directory(sessions_root, &path)?;
        if !valid_session_directory_name(&entry.file_name().to_string_lossy()) {
            return Err(CliError::StoreCorrupted(
                "unexpected daemon session directory".to_string(),
            ));
        }
        remove_session_directory(sessions_root, &path)?;
    }
    Ok(())
}

fn remove_session_directory(sessions_root: &Path, session_dir: &Path) -> Result<(), CliError> {
    verify_child_directory(sessions_root, session_dir)?;
    let entries = fs::read_dir(session_dir).map_err(|_| {
        CliError::StoreUnavailable("list daemon session artifacts failed".to_string())
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            CliError::StoreUnavailable("read daemon session artifact failed".to_string())
        })?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name != BOOTSTRAP_FILENAME && !valid_temp_bootstrap_name(&name) {
            return Err(CliError::StoreCorrupted("unexpected daemon runtime artifact".to_string()));
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| {
            CliError::StoreUnavailable("inspect daemon runtime artifact failed".to_string())
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CliError::StoreCorrupted("unsafe daemon runtime artifact".to_string()));
        }
        set_file_owner_only_path(&entry.path())?;
        fs::remove_file(entry.path()).map_err(|_| {
            CliError::StoreUnavailable("remove daemon runtime artifact failed".to_string())
        })?;
    }
    fs::remove_dir(session_dir).map_err(|_| {
        CliError::StoreUnavailable("remove daemon runtime directory failed".to_string())
    })
}

fn valid_session_directory_name(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn valid_temp_bootstrap_name(value: &str) -> bool {
    value.strip_prefix(TEMP_BOOTSTRAP_PREFIX).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(unix)]
fn open_lock_file(path: &Path) -> Result<File, CliError> {
    use rustix::fs::{Mode, OFlags, openat};
    use std::os::fd::OwnedFd;

    let descriptor: OwnedFd = openat(
        rustix::fs::CWD,
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| CliError::StoreUnavailable("open project daemon lock failed".to_string()))?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_lock_file(path: &Path) -> Result<File, CliError> {
    let metadata = fs::symlink_metadata(path);
    if metadata.as_ref().is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(CliError::StoreCorrupted("unsafe project daemon lock path".to_string()));
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .map_err(|_| CliError::StoreUnavailable("open project daemon lock failed".to_string()))
}

#[cfg(unix)]
fn set_directory_owner_only(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        CliError::StoreUnavailable("inspect daemon directory permissions failed".to_string())
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::StoreCorrupted("unsafe daemon directory".to_string()));
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)
        .map_err(|_| CliError::StoreUnavailable("secure daemon directory failed".to_string()))
}

#[cfg(not(unix))]
fn set_directory_owner_only(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

#[cfg(unix)]
fn set_file_owner_only(file: &File) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = file
        .metadata()
        .map_err(|_| {
            CliError::StoreUnavailable("inspect daemon lock permissions failed".to_string())
        })?
        .permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)
        .map_err(|_| CliError::StoreUnavailable("secure daemon lock file failed".to_string()))
}

#[cfg(not(unix))]
fn set_file_owner_only(_file: &File) -> Result<(), CliError> {
    Ok(())
}

#[cfg(unix)]
fn set_file_owner_only_path(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        CliError::StoreUnavailable("inspect daemon artifact permissions failed".to_string())
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CliError::StoreCorrupted("unsafe daemon artifact".to_string()));
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)
        .map_err(|_| CliError::StoreUnavailable("secure daemon artifact failed".to_string()))
}

#[cfg(not(unix))]
fn set_file_owner_only_path(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "filesystem fixtures are asserted")]
mod tests {
    use super::*;
    use xtrace_domain::RuntimeSessionId;

    fn temp_root() -> tempfile::TempDir {
        tempfile::Builder::new().prefix("xtrace-daemon-lock-").tempdir().expect("temp root")
    }

    #[test]
    fn project_lock_is_exclusive_and_released_on_drop() {
        let root = temp_root();
        let first = acquire_project_lock(root.path()).expect("first lock");
        assert!(matches!(acquire_project_lock(root.path()), Err(CliError::DaemonAlreadyRunning)));
        drop(first);
        let _second = acquire_project_lock(root.path()).expect("lock released");
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_project_lock_is_rejected_without_changing_link_target() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = temp_root();
        let lock = acquire_project_lock(root.path()).expect("create project lock");
        drop(lock);
        let lock_path = root.path().join(DAEMON_DIRECTORY).join(LOCK_FILENAME);
        let external_link = root.path().join("linked-lock");
        fs::hard_link(&lock_path, &external_link).expect("hardlink lock");
        let before = fs::metadata(&external_link).expect("linked metadata");
        let before_mode = before.permissions().mode() & 0o777;
        let before_bytes = fs::read(&external_link).expect("linked contents");

        assert!(matches!(acquire_project_lock(root.path()), Err(CliError::StoreCorrupted(_))));
        assert_eq!(fs::read(&external_link).expect("unchanged contents"), before_bytes);
        assert_eq!(
            fs::metadata(&external_link).expect("unchanged metadata").permissions().mode() & 0o777,
            before_mode
        );
    }

    #[cfg(unix)]
    #[test]
    fn replaced_project_lock_path_is_rejected_by_descriptor_identity_check() {
        let root = temp_root();
        let _initial = acquire_project_lock(root.path()).expect("create project lock");
        let lock_path = root.path().join(DAEMON_DIRECTORY).join(LOCK_FILENAME);
        let opened = open_lock_file(&lock_path).expect("open lock descriptor");
        let replaced_path = root.path().join("previous-lock");
        fs::rename(&lock_path, &replaced_path).expect("rename lock path");
        fs::write(&lock_path, b"").expect("replace lock path");
        assert!(matches!(
            verify_lock_identity(&opened, &lock_path),
            Err(CliError::StoreCorrupted(_))
        ));
    }

    #[test]
    fn session_cleanup_removes_only_known_bootstrap_artifacts() {
        let root = temp_root();
        let id = RuntimeSessionId::new();
        let mut runtime = RuntimeDirectory::create(root.path(), id).expect("runtime dir");
        fs::write(runtime.path().join(BOOTSTRAP_FILENAME), b"secret fixture")
            .expect("bootstrap fixture");
        runtime.cleanup().expect("cleanup");
        assert!(!runtime.path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_runtime_root_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;
        let root = temp_root();
        let target = root.path().join("target");
        fs::create_dir(&target).expect("target");
        let daemon = root.path().join(DAEMON_DIRECTORY);
        symlink(&target, &daemon).expect("symlink");
        assert!(matches!(
            RuntimeDirectory::create(root.path(), RuntimeSessionId::new()),
            Err(CliError::StoreCorrupted(_))
        ));
        assert_eq!(fs::read_dir(target).expect("target entries").count(), 0);
    }
}
