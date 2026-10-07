//! Project-scoped lock and private runtime-artifact directory for `xtrace daemon`.

use std::fs::File;
use std::path::{Path, PathBuf};

use xtrace_domain::RuntimeSessionId;
use xtrace_runtime::private_storage::AdmittedPrivateRoot;

use crate::error::CliError;

const DAEMON_DIRECTORY: &str = ".daemon";
const SESSION_DIRECTORY: &str = "sessions";
const LOCK_FILENAME: &str = "project.lock";
const BOOTSTRAP_FILENAME: &str = "bootstrap.json";
const TEMP_BOOTSTRAP_PREFIX: &str = ".bootstrap.json.tmp-";
const MAX_SESSIONS: usize = 64;

/// Holds the advisory lock and admitted roots for the lifetime of a project daemon.
pub(crate) struct ProjectDaemonLock {
    _file: File,
    _daemon_root: AdmittedPrivateRoot,
}

/// Owns one session's private runtime directory and removes it on drop.
pub(crate) struct RuntimeDirectory {
    path: PathBuf,
    session_name: String,
    _daemon_root: AdmittedPrivateRoot,
    sessions_root: AdmittedPrivateRoot,
    session_root: AdmittedPrivateRoot,
    active: bool,
    cleanup_on_drop: bool,
}

impl RuntimeDirectory {
    /// Creates a unique private session directory after removing only recognized stale files.
    pub(crate) fn create(
        project_root: &AdmittedPrivateRoot,
        runtime_session_id: RuntimeSessionId,
    ) -> Result<Self, CliError> {
        project_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
        let daemon_root = project_root
            .open_or_create_private_child(DAEMON_DIRECTORY)
            .map_err(|_| CliError::PrivateStorageUnavailable)?;
        let sessions_root = daemon_root
            .open_or_create_private_child(SESSION_DIRECTORY)
            .map_err(|_| CliError::PrivateStorageUnavailable)?;
        clean_stale_sessions(&sessions_root)?;

        let session_name = runtime_session_id.to_string();
        let session_root = sessions_root
            .create_private_child(&session_name)
            .map_err(|_| CliError::PrivateStorageUnavailable)?;
        let path = session_root.path().to_path_buf();
        Ok(Self {
            path,
            session_name,
            _daemon_root: daemon_root,
            sessions_root,
            session_root,
            active: true,
            cleanup_on_drop: true,
        })
    }

    /// Returns the unique session directory.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Removes only recognized bootstrap files through the admitted session descriptor.
    pub(crate) fn cleanup(&mut self) -> Result<(), CliError> {
        if !self.active {
            return Ok(());
        }
        remove_session_directory(&self.sessions_root, &self.session_name, &self.session_root)?;
        self.active = false;
        Ok(())
    }

    /// Leaves recognized artifacts for the next locked start after process exit.
    pub(crate) fn defer_drop_cleanup(&mut self) {
        self.cleanup_on_drop = false;
    }
}

impl Drop for RuntimeDirectory {
    fn drop(&mut self) {
        if self.cleanup_on_drop
            && let Err(error) = self.cleanup()
        {
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
/// The lock coordinates cooperating processes. Same-user hostile namespace
/// mutation remains outside this capability's guarantee.
pub(crate) fn acquire_project_lock(
    project_root: &AdmittedPrivateRoot,
) -> Result<ProjectDaemonLock, CliError> {
    project_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
    let daemon_root = project_root
        .open_or_create_private_child(DAEMON_DIRECTORY)
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    let file = daemon_root
        .open_or_create_private_file(LOCK_FILENAME)
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    if !file.metadata().is_ok_and(|metadata| metadata.len() == 0) {
        return Err(CliError::PrivateStorageUnavailable);
    }
    daemon_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
    match fs4::FileExt::try_lock(&file) {
        Ok(()) => Ok(ProjectDaemonLock { _file: file, _daemon_root: daemon_root }),
        Err(fs4::TryLockError::WouldBlock) => Err(CliError::DaemonAlreadyRunning),
        Err(fs4::TryLockError::Error(_)) => Err(CliError::PrivateStorageUnavailable),
    }
}

fn clean_stale_sessions(sessions_root: &AdmittedPrivateRoot) -> Result<(), CliError> {
    let names = sessions_root
        .bounded_child_names(MAX_SESSIONS)
        .map_err(|_| CliError::PrivateStorageUnavailable)?;
    for name in names {
        if !valid_session_directory_name(&name) {
            return Err(CliError::PrivateStorageUnavailable);
        }
        let session = sessions_root
            .open_private_child(&name)
            .map_err(|_| CliError::PrivateStorageUnavailable)?;
        remove_session_directory(sessions_root, &name, &session)?;
    }
    sessions_root.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)
}

fn remove_session_directory(
    sessions_root: &AdmittedPrivateRoot,
    session_name: &str,
    session: &AdmittedPrivateRoot,
) -> Result<(), CliError> {
    let names = session.bounded_child_names(9).map_err(|_| CliError::PrivateStorageUnavailable)?;
    for name in names {
        if name != BOOTSTRAP_FILENAME && !valid_temp_bootstrap_name(&name) {
            return Err(CliError::PrivateStorageUnavailable);
        }
        session.remove_private_file(&name).map_err(|_| CliError::PrivateStorageUnavailable)?;
    }
    session.revalidate().map_err(|_| CliError::PrivateStorageUnavailable)?;
    sessions_root
        .remove_private_child(session_name)
        .map_err(|_| CliError::PrivateStorageUnavailable)
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "filesystem fixtures are asserted")]
mod tests {
    use super::*;
    use std::fs;
    use xtrace_domain::RuntimeSessionId;

    #[test]
    fn temp_bootstrap_prefix_matches_daemon_definition() {
        assert_eq!(TEMP_BOOTSTRAP_PREFIX, xtrace_daemon::bootstrap::TEMP_BOOTSTRAP_PREFIX);
    }

    fn temp_root() -> tempfile::TempDir {
        let scratch = std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
            .map(PathBuf::from)
            .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required");
        AdmittedPrivateRoot::open(&scratch).expect("admitted private test scratch");
        tempfile::Builder::new()
            .prefix("xtrace-daemon-lock-")
            .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .tempdir_in(scratch)
            .expect("temp root")
    }

    #[test]
    fn project_lock_is_exclusive_and_released_on_drop() {
        let root = temp_root();
        let admitted = AdmittedPrivateRoot::open(root.path()).expect("admitted root");
        let first = acquire_project_lock(&admitted).expect("first lock");
        assert!(matches!(acquire_project_lock(&admitted), Err(CliError::DaemonAlreadyRunning)));
        drop(first);
        let _second = acquire_project_lock(&admitted).expect("lock released");
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_project_lock_is_rejected_without_changing_link_target() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = temp_root();
        let admitted = AdmittedPrivateRoot::open(root.path()).expect("admitted root");
        let lock = acquire_project_lock(&admitted).expect("create project lock");
        drop(lock);
        let lock_path = root.path().join(DAEMON_DIRECTORY).join(LOCK_FILENAME);
        let external_link = root.path().join("linked-lock");
        fs::hard_link(&lock_path, &external_link).expect("hardlink lock");
        let before = fs::metadata(&external_link).expect("linked metadata");
        let before_mode = before.permissions().mode() & 0o777;
        let before_bytes = fs::read(&external_link).expect("linked contents");

        assert!(matches!(
            acquire_project_lock(&admitted),
            Err(CliError::PrivateStorageUnavailable)
        ));
        assert_eq!(fs::read(&external_link).expect("unchanged contents"), before_bytes);
        assert_eq!(
            fs::metadata(&external_link).expect("unchanged metadata").permissions().mode() & 0o777,
            before_mode
        );
    }

    #[test]
    fn session_cleanup_removes_only_known_bootstrap_artifacts() {
        let root = temp_root();
        let id = RuntimeSessionId::new();
        let admitted = AdmittedPrivateRoot::open(root.path()).expect("admitted root");
        let mut runtime = RuntimeDirectory::create(&admitted, id).expect("runtime dir");
        {
            // Owner-only whatever the process umask is; cleanup admits it as a private file.
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut fixture = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(runtime.path().join(BOOTSTRAP_FILENAME))
                .expect("bootstrap fixture");
            fixture.write_all(b"secret fixture").expect("bootstrap fixture bytes");
        }
        runtime.cleanup().expect("cleanup");
        assert!(!runtime.path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_runtime_root_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;
        let root = temp_root();
        let admitted = AdmittedPrivateRoot::open(root.path()).expect("admitted root");
        let target = root.path().join("target");
        fs::create_dir(&target).expect("target");
        let daemon = root.path().join(DAEMON_DIRECTORY);
        symlink(&target, &daemon).expect("symlink");
        assert!(matches!(
            RuntimeDirectory::create(&admitted, RuntimeSessionId::new()),
            Err(CliError::PrivateStorageUnavailable)
        ));
        assert_eq!(fs::read_dir(target).expect("target entries").count(), 0);
    }
}
