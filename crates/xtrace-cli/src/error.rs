//! CLI error type.
//!
//! Every CLI failure is represented as a [`CliError`] so the binary
//! can emit a single machine-readable error document and exit with a
//! stable status code.

use xtrace_domain::AppError;
use xtrace_domain::ErrorCategory;

/// CLI-side error. Either an [`AppError`] from the application facade
/// or an early-failure (invalid argument, missing directory).
#[derive(Debug)]
pub enum CliError {
    /// Application facade returned an error.
    App(AppError),
    /// A CLI argument or environment value is invalid.
    InvalidArgument(String),
    /// The supplied project directory could not be located.
    ProjectDirectoryMissing(String),
    /// The local store is corrupted beyond recovery.
    StoreCorrupted(String),
    /// The local store cannot be reached (I/O error).
    StoreUnavailable(String),
}

impl CliError {
    /// Returns the exit code associated with the error category.
    /// The mapping follows the standard exit-code conventions: `2`
    /// for argument errors, `3` for not-found, `4` for conflicts, and
    /// `1` for every other failure so scripts do not need to
    /// distinguish internal categories.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::App(err) => exit_code_for_category(err.category),
            Self::InvalidArgument(_) => 2,
            Self::ProjectDirectoryMissing(_) => 3,
            Self::StoreCorrupted(_) => 4,
            Self::StoreUnavailable(_) => 5,
        }
    }
}

/// Returns the canonical CLI exit code for a domain error category.
pub(crate) fn exit_code_for_category(category: ErrorCategory) -> i32 {
    match category {
        ErrorCategory::Validation => 2,
        ErrorCategory::NotFound => 3,
        ErrorCategory::Conflict => 4,
        ErrorCategory::Compatibility => 6,
        ErrorCategory::Permission => 7,
        ErrorCategory::Policy => 8,
        ErrorCategory::Resource => 5,
        ErrorCategory::Transport => 5,
        ErrorCategory::Corruption => 4,
        ErrorCategory::Internal => 1,
        ErrorCategory::Cancelled => 1,
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::App(err) => f.write_str(&err.message),
            Self::InvalidArgument(message) => f.write_str(message),
            Self::ProjectDirectoryMissing(message) => {
                write!(f, "project directory missing: {message}")
            }
            Self::StoreCorrupted(message) => write!(f, "store corrupted: {message}"),
            Self::StoreUnavailable(message) => write!(f, "store unavailable: {message}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<AppError> for CliError {
    fn from(err: AppError) -> Self {
        Self::App(err)
    }
}

impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self {
        Self::StoreUnavailable(err.to_string())
    }
}
