//! Path resolution for the local store.
//!
//! Every CLI command resolves a [`StoreLocator`] from the supplied
//! `--project-dir` flag and a layout convention. Slice 1A keeps the
//! layout intentionally flat: each project directory owns exactly
//! one `metadata.sqlite3` file at its root. The layout grows in a
//! later slice when objects, sources, exports, and backups move into
//! their own subdirectories.

use std::path::{Path, PathBuf};

use xtrace_store::SqliteStore;
use xtrace_store::{OpenOptions, StoreError};

use crate::error::CliError;

/// Resolved path of the local SQLite database for a project.
#[derive(Clone, Debug)]
pub struct StoreLocator {
    /// Absolute, canonical path of the project directory.
    pub project_dir: PathBuf,
    /// Absolute path of the SQLite database file.
    pub database_path: PathBuf,
}

impl StoreLocator {
    /// Resolves the locator from the supplied project directory.
    ///
    /// The project directory must exist; the CLI errors out early
    /// with [`CliError::ProjectDirectoryMissing`] when it does not.
    /// The database path is the canonical `metadata.sqlite3` file
    /// inside the directory.
    pub fn from_project_dir(project_dir: &Path) -> Result<Self, CliError> {
        if !project_dir.exists() {
            return Err(CliError::ProjectDirectoryMissing(project_dir.display().to_string()));
        }
        if !project_dir.is_dir() {
            return Err(CliError::InvalidArgument(format!(
                "project path is not a directory: {}",
                project_dir.display()
            )));
        }
        let canonical = project_dir
            .canonicalize()
            .map_err(|err| CliError::StoreUnavailable(err.to_string()))?;
        let database_path = canonical.join("metadata.sqlite3");
        Ok(Self { project_dir: canonical, database_path })
    }

    /// Opens the store. The parent directory is guaranteed to exist
    /// by [`from_project_dir`]; this call only fails for genuine
    /// storage failures or schema mismatches.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::StoreUnavailable`] for I/O failures,
    /// [`CliError::StoreCorrupted`] when the on-disk schema is
    /// incompatible, and the wrapped [`AppError`] when the
    /// application facade rejects a command.
    pub fn open_store(&self) -> Result<SqliteStore, CliError> {
        let options = OpenOptions::default();
        SqliteStore::open(&self.database_path, options).map_err(map_store_error)
    }
}

/// Maps [`StoreError`] categories into [`CliError`].
fn map_store_error(err: StoreError) -> CliError {
    use xtrace_store::StoreErrorKind;
    match err.kind() {
        StoreErrorKind::Corruption | StoreErrorKind::SchemaIncompatible => {
            CliError::StoreCorrupted(err.message().to_string())
        }
        StoreErrorKind::Transport => CliError::StoreUnavailable(err.message().to_string()),
        _ => CliError::StoreUnavailable(err.message().to_string()),
    }
}
