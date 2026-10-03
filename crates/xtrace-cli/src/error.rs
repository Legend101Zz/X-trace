//! CLI error type.
//!
//! Every CLI failure is represented as a [`CliError`] so the binary
//! can emit a single machine-readable error document and exit with a
//! stable status code.

use xtrace_daemon::ProtocolErrorCode;
use xtrace_domain::AppError;
use xtrace_domain::ErrorCategory;

/// CLI-side error. Either an [`AppError`] from the application facade
/// or an early-failure (invalid argument, missing directory, missing
/// repository pointer, ...).
#[derive(Debug)]
pub enum CliError {
    /// Application facade returned an error.
    App(AppError),
    /// A CLI argument or environment value is invalid.
    InvalidArgument(String),
    /// The supplied project directory could not be located.
    ProjectDirectoryMissing(String),
    /// The local store schema is newer than this binary supports.
    StoreSchemaNewer(String),
    /// The local store schema is older than this binary supports.
    StoreSchemaOlder(String),
    /// The local store is corrupted beyond recovery.
    StoreCorrupted(String),
    /// The local store cannot be reached (I/O error).
    StoreUnavailable(String),
    /// Another daemon currently holds this project's advisory lock.
    DaemonAlreadyRunning,
    /// Durable recording daemon support is unavailable on this platform.
    DaemonUnsupportedPlatform,
    /// Daemon operation failed with a stable daemon-owned error code.
    DaemonFailure(ProtocolErrorCode),
    /// Direct runtime launch or process supervision failed.
    #[cfg(unix)]
    Run(xtrace_runtime::java::LaunchError),
    /// Direct Node launch or process supervision failed.
    #[cfg(unix)]
    NodeRun(xtrace_runtime::node::LaunchError),
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
            Self::StoreSchemaNewer(_) => 6,
            Self::StoreSchemaOlder(_) => 6,
            Self::StoreCorrupted(_) => 4,
            Self::StoreUnavailable(_) => 5,
            Self::DaemonAlreadyRunning => 5,
            Self::DaemonUnsupportedPlatform => 6,
            Self::DaemonFailure(_) => 5,
            #[cfg(unix)]
            Self::Run(err) => err.exit_code(),
            #[cfg(unix)]
            Self::NodeRun(err) => err.exit_code(),
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
            Self::StoreSchemaNewer(message) => write!(f, "store schema newer: {message}"),
            Self::StoreSchemaOlder(message) => write!(f, "store schema older: {message}"),
            Self::StoreCorrupted(message) => write!(f, "store corrupted: {message}"),
            Self::StoreUnavailable(message) => write!(f, "store unavailable: {message}"),
            Self::DaemonAlreadyRunning => {
                f.write_str("a daemon is already running for this project")
            }
            Self::DaemonUnsupportedPlatform => {
                f.write_str("durable recording daemon is unsupported on this platform")
            }
            Self::DaemonFailure(code) => write!(f, "daemon operation failed ({})", code.as_str()),
            #[cfg(unix)]
            Self::Run(err) => std::fmt::Display::fmt(err, f),
            #[cfg(unix)]
            Self::NodeRun(err) => std::fmt::Display::fmt(err, f),
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
