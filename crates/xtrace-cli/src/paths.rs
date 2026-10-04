//! User-data path resolution and public repository locator files.
//!
//! Durable project state stays under the user-data home. The repository contains
//! a bounded pointer and recovery locator; neither replaces private storage
//! admission or the project and receipt proof in SQLite.
//!
//! Platform defaults:
//!
//! - macOS: `$HOME/Library/Application Support/xtrace`
//! - Linux: `${XDG_DATA_HOME:-~/.local/share}/xtrace`
//! - Windows: `%APPDATA%\xtrace`
//!
//! Database path: `<user_data_home>/projects/<project-id>/metadata.sqlite3`.
//! Repository pointer: `<repo>/.xtrace/config.toml`.

use std::path::{Path, PathBuf};

use xtrace_domain::ProjectId;

use crate::error::CliError;

/// Basename of the repository pointer file written by `xtrace init`.
#[cfg(test)]
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
const PENDING_SCHEMA_VERSION: u32 = 1;

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
#[serde(deny_unknown_fields)]
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

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingInit {
    schema_version: u32,
    repository_fingerprint: String,
    project_id: ProjectId,
    data_home: PathBuf,
    display_name_digest: String,
    idempotency_key_digest: String,
    canonical_input_digest: String,
}

impl PendingInit {
    pub(crate) fn new(
        repository_fingerprint: String,
        project_id: ProjectId,
        data_home: PathBuf,
        display_name: &str,
        idempotency_key: &str,
        canonical_repo_path: &str,
    ) -> Result<Self, CliError> {
        if !data_home.is_absolute()
            || data_home.as_os_str().as_encoded_bytes().len() > crate::pointer_io::MAX_PATH_BYTES
        {
            return Err(CliError::InvalidArgument(
                "resolved data home is invalid or exceeds its path limit".into(),
            ));
        }
        let display_name_digest = digest(display_name);
        let idempotency_key_digest = digest(idempotency_key);
        let canonical_input_digest =
            digest(&format!("{canonical_repo_path}\n{display_name}\n{idempotency_key}"));
        Ok(Self {
            schema_version: PENDING_SCHEMA_VERSION,
            repository_fingerprint,
            project_id,
            data_home: normalize_absolute_path(&data_home)?,
            display_name_digest,
            idempotency_key_digest,
            canonical_input_digest,
        })
    }

    pub(crate) fn project_id(&self) -> ProjectId {
        self.project_id
    }
    pub(crate) fn data_home(&self) -> &Path {
        &self.data_home
    }

    pub(crate) fn serialized(&self) -> Result<Vec<u8>, CliError> {
        let body = toml::to_string_pretty(self).map_err(|_| {
            CliError::StoreCorrupted("could not serialize init recovery metadata".into())
        })?;
        if body.len() > crate::pointer_io::PENDING_MAX_BYTES {
            return Err(CliError::StoreCorrupted(
                "init recovery metadata exceeds its size limit".into(),
            ));
        }
        Ok(body.into_bytes())
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, CliError> {
        if bytes.len() > crate::pointer_io::PENDING_MAX_BYTES {
            return Err(CliError::StoreCorrupted(
                "init recovery metadata exceeds its size limit".into(),
            ));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| CliError::StoreCorrupted("init recovery metadata is not UTF-8".into()))?;
        let marker: Self = toml::from_str(text)
            .map_err(|_| CliError::StoreCorrupted("init recovery metadata is invalid".into()))?;
        if marker.schema_version != PENDING_SCHEMA_VERSION
            || !marker.data_home.is_absolute()
            || marker.data_home.as_os_str().as_encoded_bytes().len()
                > crate::pointer_io::MAX_PATH_BYTES
            || normalize_absolute_path(&marker.data_home)
                .map_or(true, |path| path != marker.data_home)
        {
            return Err(CliError::StoreCorrupted(
                "init recovery metadata has unsupported identity".into(),
            ));
        }
        Ok(marker)
    }
}

pub(crate) fn normalize_absolute_path(path: &Path) -> Result<PathBuf, CliError> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > crate::pointer_io::MAX_PATH_BYTES
    {
        return Err(CliError::InvalidArgument(
            "data home must be an absolute path within the supported limit".into(),
        ));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                normalized.push(component.as_os_str())
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::Normal(value) => normalized.push(value),
        }
    }
    Ok(normalized)
}

fn digest(value: &str) -> String {
    format!("b3:{}", blake3::hash(value.as_bytes()).to_hex())
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
            return Err(CliError::StoreCorrupted("pointer data home is not absolute".into()));
        }
        if value.data_home.as_os_str().as_encoded_bytes().len() > crate::pointer_io::MAX_PATH_BYTES
        {
            return Err(CliError::StoreCorrupted(
                "pointer data home exceeds its path limit".into(),
            ));
        }
        if normalize_absolute_path(&value.data_home).map_or(true, |path| path != value.data_home) {
            return Err(CliError::StoreCorrupted("pointer data home is not normalized".into()));
        }
        Ok(Self {
            schema_version: value.schema_version,
            project_id: value.project_id,
            data_home: value.data_home,
        })
    }
}

impl RepositoryPointer {
    /// Writes the pointer without replacing a pointer already present.
    pub fn write(&self, repo: &Path) -> Result<(), CliError> {
        if !self.data_home.is_absolute() {
            return Err(CliError::StoreCorrupted(
                "refusing pointer with non-absolute data home".into(),
            ));
        }
        if normalize_absolute_path(&self.data_home).map_or(true, |path| path != self.data_home) {
            return Err(CliError::StoreCorrupted(
                "refusing pointer with non-normalized data home".into(),
            ));
        }
        let body = self.serialized()?;
        let lock = crate::pointer_io::RepositoryInitLock::acquire(repo)?;
        self.write_locked(&lock, &body)
    }

    pub(crate) fn write_locked(
        &self,
        lock: &crate::pointer_io::RepositoryInitLock,
        body: &[u8],
    ) -> Result<(), CliError> {
        if body.len() > crate::pointer_io::POINTER_MAX_BYTES {
            return Err(CliError::StoreCorrupted(
                "repository pointer exceeds its size limit".into(),
            ));
        }
        if let Some(existing) = lock.read(POINTER_FILENAME, crate::pointer_io::POINTER_MAX_BYTES)? {
            let existing = Self::parse(&existing)?;
            return if existing == *self {
                Ok(())
            } else {
                Err(CliError::StoreCorrupted(
                    "repository pointer conflicts with existing metadata".into(),
                ))
            };
        }
        lock.publish(POINTER_FILENAME, body, crate::pointer_io::POINTER_MAX_BYTES)
    }

    pub(crate) fn read_locked(
        lock: &crate::pointer_io::RepositoryInitLock,
    ) -> Result<Option<Self>, CliError> {
        lock.read(POINTER_FILENAME, crate::pointer_io::POINTER_MAX_BYTES)?
            .map(|bytes| Self::parse(&bytes))
            .transpose()
    }

    pub(crate) fn serialized(&self) -> Result<Vec<u8>, CliError> {
        if self.data_home.as_os_str().as_encoded_bytes().len() > crate::pointer_io::MAX_PATH_BYTES {
            return Err(CliError::StoreCorrupted(
                "repository data home exceeds its path limit".into(),
            ));
        }
        let body =
            toml::to_string_pretty(&RepositoryPointerToml::from(self.clone())).map_err(|_| {
                CliError::StoreCorrupted("could not serialize repository pointer".into())
            })?;
        if body.len() > crate::pointer_io::POINTER_MAX_BYTES {
            return Err(CliError::StoreCorrupted(
                "repository pointer exceeds its size limit".into(),
            ));
        }
        Ok(body.into_bytes())
    }

    /// Reads the bounded pointer file without following links.
    pub fn read(repo: &Path) -> Result<Self, CliError> {
        let bytes = crate::pointer_io::read_unlocked(
            repo,
            POINTER_FILENAME,
            crate::pointer_io::POINTER_MAX_BYTES,
        )?
        .ok_or_else(|| CliError::ProjectDirectoryMissing("repository pointer not found".into()))?;
        Self::parse(&bytes)
    }

    fn parse(bytes: &[u8]) -> Result<Self, CliError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| CliError::StoreCorrupted("repository pointer is not UTF-8".into()))?;
        let parsed: RepositoryPointerToml = toml::from_str(text)
            .map_err(|_| CliError::StoreCorrupted("repository pointer is invalid".into()))?;
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

    #[test]
    fn pointer_write_preserves_an_existing_different_pointer() {
        let dir = tempdir();
        let repo = dir.join("repo");
        std::fs::create_dir_all(&repo).expect("repo");
        let first = RepositoryPointer {
            schema_version: 1,
            project_id: ProjectId::new(),
            data_home: dir.join("data-one"),
        };
        first.write(&repo).expect("first pointer");
        let pointer_path = repo.join(POINTER_BASENAME).join(POINTER_FILENAME);
        let original = std::fs::read(&pointer_path).expect("original pointer");
        let second = RepositoryPointer {
            schema_version: 1,
            project_id: ProjectId::new(),
            data_home: dir.join("data-two"),
        };
        assert!(second.write(&repo).is_err());
        assert_eq!(std::fs::read(pointer_path).expect("preserved pointer"), original);
    }

    #[test]
    fn pointer_and_pending_serialization_enforce_utf8_byte_caps() {
        let long_escaped_path =
            PathBuf::from(format!("/{}", "\"".repeat(crate::pointer_io::MAX_PATH_BYTES - 1)));
        let pointer = RepositoryPointer {
            schema_version: 1,
            project_id: ProjectId::new(),
            data_home: long_escaped_path.clone(),
        };
        assert!(pointer.serialized().is_err());
        let pending = PendingInit::new(
            "fingerprint".into(),
            ProjectId::new(),
            long_escaped_path,
            "name",
            "key",
            "/repo",
        )
        .expect("bounded path");
        assert!(pending.serialized().is_err());
    }

    fn tempdir() -> PathBuf {
        let scratch = std::env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
            .map(PathBuf::from)
            .expect("owner-enforced XTRACE_TEST_PRIVATE_SCRATCH is required");
        xtrace_runtime::private_storage::AdmittedPrivateRoot::open(&scratch)
            .expect("admitted private test scratch");
        tempfile::Builder::new()
            .prefix("xtrace-cli-paths-")
            .tempdir_in(scratch)
            .expect("create unique test directory")
            .keep()
    }
}
