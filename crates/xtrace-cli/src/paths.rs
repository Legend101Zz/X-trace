//! User-data path resolution and repository pointer file.
//!
//! Slice 1A keeps durable project state under the user-data home
//! directory rather than inside the repository. The CLI resolves the
//! home directory at the command level in this order:
//!
//! 1. `XTRACE_DATA_HOME` when it points at an absolute path (the
//!    explicit override is used directly as the application root);
//! 2. the [`data_home`](RepositoryPointer::data_home) recorded in an
//!    existing repository pointer, when no override is set;
//! 3. the platform default, via [`UserDataPaths::home_with`].
//!
//! [`UserDataPaths::home_with`] itself only handles the override
//! followed by the platform default; the pointer is consulted by the
//! command-level resolver before that helper is called.
//!
//! Platform defaults:
//!
//! - macOS: `$HOME/Library/Application Support/xtrace`
//! - Linux: `${XDG_DATA_HOME:-~/.local/share}/xtrace`
//! - Windows: `%APPDATA%\xtrace`
//!
//! Database path:
//!
//! ```text
//! <user_data_home>/projects/<project-id>/metadata.sqlite3
//! ```
//!
//! Repository pointer:
//!
//! ```text
//! <repo>/.xtrace/config.toml
//! ```

use std::path::{Path, PathBuf};

use xtrace_domain::ProjectId;

use crate::error::CliError;

/// Basename of the repository pointer file written by `xtrace init`.
const POINTER_BASENAME: &str = ".xtrace";
/// File name of the pointer file inside `.xtrace`.
const POINTER_FILENAME: &str = "config.toml";
/// File name of the SQLite database file inside a project directory.
const DATABASE_FILENAME: &str = "metadata.sqlite3";
/// Environment variable that overrides the user-data home directory.
const USER_DATA_HOME_ENV: &str = "XTRACE_DATA_HOME";
/// Application folder name under the user-data home.
const XTRACE_FOLDER: &str = "xtrace";
/// Subdirectory that holds one folder per project.
const PROJECTS_FOLDER: &str = "projects";
/// Pointer file format version the binary understands.
const POINTER_SCHEMA_VERSION: u32 = 1;

/// Pointer file written into the repository root by `xtrace init`.
///
/// The file is intentionally tiny: it contains the project identifier
/// and the absolute path of the user-data home used at init time.
/// Future slices add more fields (active policy versions, capture
/// settings, ...) without changing the file format's major version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryPointer {
    /// Pointer file format version. Bumped together with schema
    /// changes that older binaries cannot read.
    pub schema_version: u32,
    /// Stable project identifier recorded at `init` time.
    pub project_id: ProjectId,
    /// Absolute path of the user-data home directory the project
    /// lives under.
    pub data_home: PathBuf,
}

/// Typed view of the on-disk TOML shape. `Serialize`/`Deserialize`
/// handle the wire format; the surrounding [`RepositoryPointer`] adds
/// validation (schema version, absolute data home) so a corrupt
/// pointer cannot silently move a project to a different storage
/// location.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct RepositoryPointerToml {
    /// Pointer file format version. Bumped together with schema
    /// changes that older binaries cannot read.
    schema_version: u32,
    /// Stable project identifier recorded at `init` time.
    project_id: ProjectId,
    /// Absolute path of the user-data home directory the project
    /// lives under.
    data_home: PathBuf,
}

impl From<RepositoryPointer> for RepositoryPointerToml {
    fn from(value: RepositoryPointer) -> Self {
        Self {
            schema_version: value.schema_version,
            project_id: value.project_id,
            data_home: value.data_home,
        }
    }
}

impl TryFrom<RepositoryPointerToml> for RepositoryPointer {
    type Error = CliError;
    fn try_from(value: RepositoryPointerToml) -> Result<Self, Self::Error> {
        if value.schema_version != POINTER_SCHEMA_VERSION {
            return Err(CliError::StoreCorrupted(format!(
                "unsupported pointer schema_version {} (binary expects {})",
                value.schema_version, POINTER_SCHEMA_VERSION
            )));
        }
        if !value.data_home.is_absolute() {
            return Err(CliError::StoreCorrupted(format!(
                "pointer data_home is not absolute: {}",
                value.data_home.display()
            )));
        }
        Ok(Self {
            schema_version: value.schema_version,
            project_id: value.project_id,
            data_home: value.data_home,
        })
    }
}

impl RepositoryPointer {
    /// Writes the pointer file to the supplied repository root.
    /// The file is written atomically: the body first lands in a
    /// sibling `.tmp` file, then `rename` swaps it into place. The
    /// parent `.xtrace` directory is created with owner-only
    /// permissions on Unix so the file cannot be read by other users.
    ///
    /// The helper fails closed on Unix: every chmod step returns
    /// [`CliError::StoreUnavailable`] on failure. If the write fails
    /// after the local database has been initialized, Slice 1A is
    /// left in a state it cannot recover from automatically: the
    /// database at `<data_home>/projects/<project_id>/` contains a
    /// project row but the repository has no `.xtrace/config.toml`
    /// pointer, and the CLI generated the project ID locally so it
    /// cannot discover the orphaned directory from a missing pointer.
    /// A subsequent `init` cannot replay the original receipt
    /// through the public path because the CLI assigns a fresh
    /// project ID on retry and the resulting pointer would resolve
    /// to a different database. Slice 1A does not redesign recovery;
    /// the bounded risk is that the orphaned
    /// `<data_home>/projects/<project_id>/` directory must be
    /// cleaned up manually.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::StoreUnavailable`] when the filesystem
    /// refuses the write or any chmod step fails; the file is never
    /// partially written.
    pub fn write(&self, repo: &Path) -> Result<(), CliError> {
        use std::fs;
        use std::io::Write as _;
        if !self.data_home.is_absolute() {
            return Err(CliError::StoreCorrupted(format!(
                "refusing to write pointer with non-absolute data_home: {}",
                self.data_home.display()
            )));
        }
        let pointer_dir = repo.join(POINTER_BASENAME);
        let pointer_path = pointer_dir.join(POINTER_FILENAME);
        fs::create_dir_all(&pointer_dir)
            .map_err(|err| CliError::StoreUnavailable(format!("create .xtrace: {err}")))?;
        // `0700` on the pointer directory prevents other users from
        // enumerating or reading the file before the rename commits.
        chmod_dir_owner_only(&pointer_dir)?;
        // Serialise the typed pointer through `toml` so a path
        // containing quotes, backslashes, or other TOML-significant
        // characters round-trips verbatim instead of corrupting the
        // file.
        let toml_value = RepositoryPointerToml::from(self.clone());
        let body = toml::to_string_pretty(&toml_value)
            .map_err(|err| CliError::StoreCorrupted(format!("serialize pointer: {err}")))?;
        let tmp = pointer_dir.join(format!("{POINTER_FILENAME}.tmp"));
        {
            let mut file = fs::File::create(&tmp)
                .map_err(|err| CliError::StoreUnavailable(format!("create tmp pointer: {err}")))?;
            file.write_all(body.as_bytes())
                .map_err(|err| CliError::StoreUnavailable(format!("write tmp pointer: {err}")))?;
            file.sync_all()
                .map_err(|err| CliError::StoreUnavailable(format!("sync tmp pointer: {err}")))?;
        }
        fs::rename(&tmp, &pointer_path)
            .map_err(|err| CliError::StoreUnavailable(format!("rename pointer: {err}")))?;
        chmod_file_owner_only(&pointer_path)?;
        Ok(())
    }

    /// Reads the pointer file from the supplied repository root.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::ProjectDirectoryMissing`] when the file is
    /// absent, [`CliError::StoreCorrupted`] when the schema version
    /// is unsupported, the data home is relative, or the body is
    /// unparseable, [`CliError::StoreUnavailable`] when the
    /// filesystem refuses the read. The CLI surfaces a missing
    /// pointer as a separate "uninitialized" error so callers can
    /// report the state truthfully.
    pub fn read(repo: &Path) -> Result<Self, CliError> {
        let pointer_path = repo.join(POINTER_BASENAME).join(POINTER_FILENAME);
        let text = std::fs::read_to_string(&pointer_path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                CliError::ProjectDirectoryMissing(format!(
                    "repository pointer not found: {}",
                    pointer_path.display()
                ))
            } else {
                CliError::StoreUnavailable(format!("read pointer: {err}"))
            }
        })?;
        let parsed: RepositoryPointerToml = toml::from_str(&text).map_err(|err| {
            CliError::StoreCorrupted(format!(
                "invalid pointer file {}: {err}",
                pointer_path.display()
            ))
        })?;
        parsed.try_into()
    }
}

/// User-data path resolver.
pub struct UserDataPaths;

impl UserDataPaths {
    /// Resolves the user-data home directory using a caller-supplied
    /// environment reader. Exposed for tests so the resolver can be
    /// exercised without mutating process-wide state.
    ///
    /// Precedence:
    ///
    /// 1. `XTRACE_DATA_HOME` when it points at an absolute path.
    /// 2. Platform-default lookup: the conventional user-data
    ///    environment variable (`XDG_DATA_HOME` on Linux,
    ///    `APPDATA` on Windows), falling back to `$HOME` when the
    ///    platform variable is unset.
    pub fn home_with<F>(env_reader: F) -> Result<PathBuf, CliError>
    where
        F: Fn(&str) -> Option<PathBuf>,
    {
        if let Some(value) = env_reader(USER_DATA_HOME_ENV) {
            // A relative override is ignored so a misconfigured shell
            // cannot push the store into the repository.
            if value.is_absolute() {
                return Ok(value);
            }
        }
        platform_user_data_home(&env_reader).ok_or_else(|| {
            CliError::StoreUnavailable(
                "could not determine user-data home; set XTRACE_DATA_HOME".to_string(),
            )
        })
    }

    /// Resolves the absolute project directory under the supplied
    /// user-data home. Used by callers that need to honour an
    /// explicit override or a pointer-recorded data home without
    /// changing the resolved default.
    pub fn project_dir_with_home(home: &Path, project_id: ProjectId) -> Result<PathBuf, CliError> {
        Ok(home.join(PROJECTS_FOLDER).join(project_id.to_string()))
    }

    /// Resolves the absolute database path under the supplied
    /// user-data home.
    pub fn database_path_with_home(
        home: &Path,
        project_id: ProjectId,
    ) -> Result<PathBuf, CliError> {
        Ok(Self::project_dir_with_home(home, project_id)?.join(DATABASE_FILENAME))
    }
}

/// Reads an absolute path from the process environment. Returns
/// `None` when the variable is unset, empty, or not an absolute path.
pub(crate) fn read_env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

/// Resolves the platform-default user-data home. The function is
/// the single source of truth for the platform-specific lookup; each
/// platform honours its conventional user-data environment variable
/// before falling back to `$HOME` when the variable is unset.
fn platform_user_data_home<F>(env_reader: &F) -> Option<PathBuf>
where
    F: Fn(&str) -> Option<PathBuf>,
{
    #[cfg(target_os = "linux")]
    {
        if let Some(value) = env_reader("XDG_DATA_HOME") {
            return Some(value.join(XTRACE_FOLDER));
        }
        if let Some(home) = env_reader("HOME") {
            return Some(home.join(".local").join("share").join(XTRACE_FOLDER));
        }
        None
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(value) = env_reader("APPDATA") {
            return Some(value.join(XTRACE_FOLDER));
        }
        env_reader("HOME").map(|home| home.join(XTRACE_FOLDER))
    }
    #[cfg(target_os = "macos")]
    {
        env_reader("HOME")
            .map(|home| home.join("Library").join("Application Support").join(XTRACE_FOLDER))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = env_reader;
        None
    }
}

/// `chmod 0700` on the supplied directory on Unix. Fails closed:
/// every metadata or chmod failure surfaces as
/// [`CliError::StoreUnavailable`]. Off Unix, the helper returns
/// `Ok(())` because Windows ACLs are managed through other APIs
/// and no portable `chmod` equivalent exists.
#[cfg(unix)]
fn chmod_dir_owner_only(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = std::fs::metadata(path).map_err(|err| {
        CliError::StoreUnavailable(format!("stat directory {}: {err}", path.display()))
    })?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)
        .map_err(|err| CliError::StoreUnavailable(format!("chmod 0700 {}: {err}", path.display())))
}

/// `chmod 0700` on the supplied directory on Unix. Returns `Ok(())`
/// off Unix (documented no-op).
#[cfg(not(unix))]
fn chmod_dir_owner_only(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

/// `chmod 0600` on the supplied file on Unix. Fails closed: every
/// metadata or chmod failure (including a missing file) surfaces as
/// [`CliError::StoreUnavailable`]. Off Unix, the helper returns
/// `Ok(())`.
#[cfg(unix)]
fn chmod_file_owner_only(path: &Path) -> Result<(), CliError> {
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt as _;

    let path_metadata = std::fs::symlink_metadata(path).map_err(|_| {
        CliError::StoreUnavailable(format!("inspect file path {} failed", path.display()))
    })?;
    validate_database_file_metadata(&path_metadata)?;

    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        let descriptor = rustix::fs::openat(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| {
            CliError::StoreCorrupted("database path is not a safe regular file".to_string())
        })?;
        let file = std::fs::File::from(descriptor);
        let descriptor_metadata = file.metadata().map_err(|_| {
            CliError::StoreUnavailable(format!("inspect file {} failed", path.display()))
        })?;
        validate_database_file_metadata(&descriptor_metadata)?;
        ensure_same_file(&descriptor_metadata, &path_metadata)?;
        let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        std::fs::set_permissions(descriptor_path, std::fs::Permissions::from_mode(0o600)).map_err(
            |_| CliError::StoreUnavailable(format!("secure file {} failed", path.display())),
        )?;
        let updated_descriptor = file.metadata().map_err(|_| {
            CliError::StoreUnavailable(format!("inspect file {} failed", path.display()))
        })?;
        validate_database_file_metadata(&updated_descriptor)?;
        ensure_same_file(&updated_descriptor, &path_metadata)?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        // On platforms with `fchmodat` no-follow support, this repairs mode-000
        // files without needing a read-capable open descriptor.
        rustix::fs::chmodat(
            rustix::fs::CWD,
            path,
            rustix::fs::Mode::from_bits_truncate(0o600),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| {
            CliError::StoreUnavailable(format!("secure file {} failed", path.display()))
        })?;
        let updated_path = std::fs::symlink_metadata(path).map_err(|_| {
            CliError::StoreUnavailable(format!("inspect file path {} failed", path.display()))
        })?;
        validate_database_file_metadata(&updated_path)?;
        ensure_same_file(&updated_path, &path_metadata)
    }
}

#[cfg(unix)]
fn validate_database_file_metadata(metadata: &std::fs::Metadata) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt as _;

    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(CliError::StoreCorrupted(
            "database path must be a single-link regular file".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt as _;

    if left.dev() != right.dev() || left.ino() != right.ino() {
        return Err(CliError::StoreCorrupted(
            "database path changed during validation".to_string(),
        ));
    }
    Ok(())
}

/// `chmod 0600` on the supplied file on Unix. Returns `Ok(())` off
/// Unix (documented no-op).
#[cfg(not(unix))]
fn chmod_file_owner_only(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

/// Sets owner-only permissions on the project directory. Callers
/// must invoke this helper *before* the SQLite database file is
/// created so the directory's `0700` mode prevents another user on
/// the host from enumerating or traversing into the project before
/// the database file is born. Fails closed on Unix.
pub fn restrict_project_dir(project_dir: &Path) -> Result<(), CliError> {
    chmod_dir_owner_only(project_dir)
}

/// Creates the SQLite database file with mode `0600` (using
/// [`std::fs::OpenOptions`] plus
/// [`std::os::unix::fs::OpenOptionsExt::mode`]) and repairs an existing
/// file without truncating it. The mode is verified before
/// [`xtrace_store::SqliteStore::open`] is called. The helper is invoked
/// from `init` so the file is born owner-only and SQLite does not briefly
/// expose it with the directory's default mode. Fails closed on Unix;
/// returns `Ok(())` off Unix (documented no-op).
pub fn precreate_database_file(database: &Path) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt as _;
        let created = OpenOptions::new()
            .create(true)
            .create_new(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(database);
        match created {
            Ok(file) => chmod_open_file_owner_only(&file, database)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                chmod_file_owner_only(database)?;
            }
            Err(err) => {
                return Err(CliError::StoreUnavailable(format!(
                    "precreate database {}: {err}",
                    database.display()
                )));
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = database;
    }
    Ok(())
}

#[cfg(unix)]
fn chmod_open_file_owner_only(file: &std::fs::File, path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt as _;

    let descriptor_metadata = file.metadata().map_err(|_| {
        CliError::StoreUnavailable(format!("inspect file {} failed", path.display()))
    })?;
    validate_database_file_metadata(&descriptor_metadata)?;
    let path_metadata = std::fs::symlink_metadata(path).map_err(|_| {
        CliError::StoreUnavailable(format!("inspect file path {} failed", path.display()))
    })?;
    validate_database_file_metadata(&path_metadata)?;
    ensure_same_file(&descriptor_metadata, &path_metadata)?;
    rustix::fs::fchmod(file, rustix::fs::Mode::from_bits_truncate(0o600)).map_err(|_| {
        CliError::StoreUnavailable(format!("secure file {} failed", path.display()))
    })?;
    let updated = file.metadata().map_err(|_| {
        CliError::StoreUnavailable(format!("inspect file {} failed", path.display()))
    })?;
    validate_database_file_metadata(&updated)?;
    if updated.dev() != path_metadata.dev() || updated.ino() != path_metadata.ino() {
        return Err(CliError::StoreCorrupted(
            "database path changed during permission repair".to_string(),
        ));
    }
    Ok(())
}

/// Sets owner-only permissions on the SQLite database file. Callers
/// invoke this helper immediately after
/// [`xtrace_store::SqliteStore::open`] returns so the file is never
/// readable by another user even when it was just created. Fails
/// closed on Unix.
pub fn restrict_database_file(database: &Path) -> Result<(), CliError> {
    chmod_file_owner_only(database)
}

/// Sets owner-only permissions on a project directory and the SQLite
/// file it contains when the platform supports it. The helper is
/// idempotent and is used by every CLI entry point that touches a
/// previously-created project directory (`status`, `open`) so a
/// directory left loose by an older binary is repaired on the next
/// invocation. Fails closed on Unix: a chmod failure on either the
/// directory or the database file surfaces as
/// [`CliError::StoreUnavailable`]. The database path is checked as a regular,
/// non-symlink, single-link file before either repair; Unix file-mode repair
/// uses a no-follow descriptor or chmod operation and verifies file identity.
pub fn secure_project_dir(project_dir: &Path) -> Result<(), CliError> {
    let database = project_dir.join(DATABASE_FILENAME);
    let database_exists = match std::fs::symlink_metadata(&database) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(CliError::StoreCorrupted(
                "project database must be a real file".to_string(),
            ));
        }
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                if metadata.nlink() != 1 {
                    return Err(CliError::StoreCorrupted(
                        "project database must have exactly one filesystem link".to_string(),
                    ));
                }
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => {
            return Err(CliError::StoreUnavailable(
                "inspect project database path failed".to_string(),
            ));
        }
    };
    chmod_dir_owner_only(project_dir)?;
    if database_exists {
        chmod_file_owner_only(&database)?;
    }
    Ok(())
}

#[cfg(test)]
// Tests intentionally panic on invariant violations because the
// failure mode is "test failed", not "library panicked".
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests assert on fallible fixture data")]
mod tests {
    use super::*;

    #[test]
    fn home_with_drives_project_and_database_paths() {
        // The `home_with` resolver is the single source of truth
        // for the path helpers. This test exercises the path
        // helpers directly through the injected reader so the
        // layout stays consistent across call sites.
        let fake_home = PathBuf::from("/tmp/fake-home-resolver");
        let reader = |var: &str| (var == "XTRACE_DATA_HOME").then(|| fake_home.clone());
        let resolved = UserDataPaths::home_with(reader).expect("home resolves");
        assert_eq!(resolved, fake_home);
        let project_id = ProjectId::new();
        let project_dir =
            UserDataPaths::project_dir_with_home(&resolved, project_id).expect("project dir");
        assert_eq!(project_dir, fake_home.join(PROJECTS_FOLDER).join(project_id.to_string()));
        let database =
            UserDataPaths::database_path_with_home(&resolved, project_id).expect("database path");
        assert_eq!(database, project_dir.join(DATABASE_FILENAME));
    }

    #[test]
    fn user_data_home_prefers_explicit_override() {
        let resolved = UserDataPaths::home_with(|var| {
            if var == USER_DATA_HOME_ENV {
                Some(PathBuf::from("/tmp/xtrace-data-home-test"))
            } else {
                None
            }
        })
        .expect("home resolves");
        assert_eq!(resolved, PathBuf::from("/tmp/xtrace-data-home-test"));
    }

    #[test]
    fn user_data_home_rejects_relative_env() {
        // A relative override is ignored so a misconfigured shell
        // cannot push the store into the repository.
        let resolved = UserDataPaths::home_with(|var| {
            if var == USER_DATA_HOME_ENV { Some(PathBuf::from("relative/path")) } else { None }
        });
        // The injected reader returns a relative path; the
        // implementation must discard it and fall back to the
        // platform default or error.
        if let Ok(path) = resolved {
            assert!(path.is_absolute());
        }
    }

    #[test]
    fn user_data_home_uses_platform_default() {
        // No `XTRACE_DATA_HOME`, but a `HOME` is provided so the
        // platform-default branch must produce an absolute path.
        let resolved = UserDataPaths::home_with(|var| match var {
            USER_DATA_HOME_ENV => None,
            "HOME" => Some(PathBuf::from("/tmp/fake-home")),
            _ => None,
        });
        if let Ok(path) = resolved {
            assert!(path.is_absolute());
            assert!(path.starts_with("/tmp/fake-home"));
        }
    }

    #[test]
    fn user_data_home_errors_when_unset() {
        let resolved = UserDataPaths::home_with(|_| None);
        assert!(resolved.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_platform_default_uses_xdg_data_home_when_set() {
        let resolved = UserDataPaths::home_with(|var| match var {
            USER_DATA_HOME_ENV => None,
            "XDG_DATA_HOME" => Some(PathBuf::from("/tmp/xdg-data")),
            _ => None,
        })
        .expect("home resolves");
        assert_eq!(resolved, PathBuf::from("/tmp/xdg-data").join(XTRACE_FOLDER));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_platform_default_falls_back_to_home_when_xdg_unset() {
        let resolved = UserDataPaths::home_with(|var| match var {
            USER_DATA_HOME_ENV => None,
            "HOME" => Some(PathBuf::from("/tmp/linux-home")),
            _ => None,
        })
        .expect("home resolves");
        assert_eq!(
            resolved,
            PathBuf::from("/tmp/linux-home").join(".local").join("share").join(XTRACE_FOLDER)
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_platform_default_uses_appdata_when_set() {
        let resolved = UserDataPaths::home_with(|var| match var {
            USER_DATA_HOME_ENV => None,
            "APPDATA" => Some(PathBuf::from(r"C:\Users\test\AppData\Roaming")),
            _ => None,
        })
        .expect("home resolves");
        assert_eq!(resolved, PathBuf::from(r"C:\Users\test\AppData\Roaming").join(XTRACE_FOLDER));
    }

    #[test]
    fn pointer_round_trips_through_disk() {
        let dir = tempdir();
        let repo = dir.join("repo");
        std::fs::create_dir_all(&repo).expect("repo");
        let project_id = ProjectId::new();
        let data_home = dir.join("user-data");
        std::fs::create_dir_all(&data_home).expect("user-data");
        let pointer =
            RepositoryPointer { schema_version: 1, project_id, data_home: data_home.clone() };
        pointer.write(&repo).expect("write");
        let loaded = RepositoryPointer::read(&repo).expect("read");
        assert_eq!(loaded, pointer);
    }

    #[test]
    fn pointer_round_trips_paths_with_quotes_and_spaces() {
        let dir = tempdir();
        let repo = dir.join("repo");
        std::fs::create_dir_all(&repo).expect("repo");
        let project_id = ProjectId::new();
        // A path with double-quotes, single-quotes, backslashes, and
        // spaces must round-trip without manual escaping.
        let data_home = dir.join("user data \"with\" 'quotes' \\and\\ spaces");
        std::fs::create_dir_all(&data_home).expect("user-data");
        let pointer =
            RepositoryPointer { schema_version: 1, project_id, data_home: data_home.clone() };
        pointer.write(&repo).expect("write");
        let loaded = RepositoryPointer::read(&repo).expect("read");
        assert_eq!(loaded, pointer);
        assert_eq!(loaded.data_home, data_home);
    }

    #[test]
    fn read_missing_pointer_is_recoverable() {
        let dir = tempdir();
        let repo = dir.join("missing-repo");
        std::fs::create_dir_all(&repo).expect("repo");
        let err = RepositoryPointer::read(&repo).unwrap_err();
        assert!(matches!(err, CliError::ProjectDirectoryMissing(_)));
    }

    #[test]
    fn read_pointer_rejects_unsupported_schema_version() {
        let dir = tempdir();
        let repo = dir.join("repo");
        std::fs::create_dir_all(&repo).expect("repo");
        std::fs::create_dir_all(repo.join(POINTER_BASENAME)).expect("pointer dir");
        std::fs::write(
            repo.join(POINTER_BASENAME).join(POINTER_FILENAME),
            "schema_version = 99\nproject_id = \"00000000-0000-0000-0000-000000000000\"\ndata_home = \"/tmp/legacy\"\n",
        )
        .expect("write");
        let err = RepositoryPointer::read(&repo).unwrap_err();
        assert!(matches!(err, CliError::StoreCorrupted(_)));
    }

    #[test]
    fn read_pointer_rejects_relative_data_home() {
        let dir = tempdir();
        let repo = dir.join("repo");
        std::fs::create_dir_all(&repo).expect("repo");
        std::fs::create_dir_all(repo.join(POINTER_BASENAME)).expect("pointer dir");
        std::fs::write(
            repo.join(POINTER_BASENAME).join(POINTER_FILENAME),
            "schema_version = 1\nproject_id = \"00000000-0000-0000-0000-000000000000\"\ndata_home = \"relative/path\"\n",
        )
        .expect("write");
        let err = RepositoryPointer::read(&repo).unwrap_err();
        assert!(matches!(err, CliError::StoreCorrupted(_)));
    }

    #[test]
    fn write_pointer_rejects_relative_data_home() {
        let dir = tempdir();
        let repo = dir.join("repo");
        std::fs::create_dir_all(&repo).expect("repo");
        let pointer = RepositoryPointer {
            schema_version: 1,
            project_id: ProjectId::new(),
            data_home: PathBuf::from("relative/path"),
        };
        let err = pointer.write(&repo).unwrap_err();
        assert!(matches!(err, CliError::StoreCorrupted(_)));
    }

    #[cfg(unix)]
    #[test]
    fn pointer_file_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir();
        let repo = dir.join("repo");
        std::fs::create_dir_all(&repo).expect("repo");
        let pointer = RepositoryPointer {
            schema_version: 1,
            project_id: ProjectId::new(),
            data_home: dir.join("user-data"),
        };
        pointer.write(&repo).expect("write");
        let metadata = std::fs::metadata(repo.join(POINTER_BASENAME).join(POINTER_FILENAME))
            .expect("metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn project_directory_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir();
        let project_dir = dir.join("project");
        std::fs::create_dir_all(&project_dir).expect("project");
        let database = project_dir.join(DATABASE_FILENAME);
        std::fs::write(&database, b"x").expect("database");
        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o000))
            .expect("make database unreadable");
        secure_project_dir(&project_dir).expect("chmod");
        let dir_mode =
            std::fs::metadata(&project_dir).expect("dir metadata").permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(project_dir.join(DATABASE_FILENAME))
            .expect("file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "project directory must be owner-only");
        assert_eq!(file_mode, 0o600, "database file must be owner-only");
    }

    #[cfg(unix)]
    #[test]
    fn precreate_repairs_new_and_existing_mode_zero_database_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempdir();
        let project_dir = dir.join("project");
        std::fs::create_dir_all(&project_dir).expect("project");
        let database = project_dir.join(DATABASE_FILENAME);

        precreate_database_file(&database).expect("create owner-only database");
        assert_eq!(
            std::fs::metadata(&database).expect("new database metadata").permissions().mode()
                & 0o777,
            0o600
        );

        std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o000))
            .expect("make existing database unreadable");
        precreate_database_file(&database).expect("repair unreadable existing database");
        assert_eq!(
            std::fs::metadata(&database).expect("repaired database metadata").permissions().mode()
                & 0o777,
            0o600
        );
    }

    fn tempdir() -> PathBuf {
        tempfile::Builder::new()
            .prefix("xtrace-cli-paths-")
            .tempdir()
            .expect("create unique test directory")
            .keep()
    }
}
