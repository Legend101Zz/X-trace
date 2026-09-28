//! SQLite store errors.
//!
//! Every public function in `xtrace-store` returns a typed
//! [`StoreError`]. The error intentionally does not embed SQL
//! parameter values so diagnostics never smuggle a captured value
//! or a secret into logs.
//!
//! Mapping to [`xtrace_application::PortError`] happens at the
//! repository boundary; the store stays free of application-layer
//! types.

use xtrace_domain::CorrelationId;

/// Categorical view of a storage failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoreErrorKind {
    /// Caller supplied invalid input (bad UUID, out-of-range value).
    Validation,
    /// The on-disk schema is older than this binary can read.
    SchemaOlder,
    /// The on-disk schema is newer than this binary can read.
    SchemaNewer,
    /// The on-disk schema is incompatible in a way that cannot be
    /// repaired by the bundled migrations.
    SchemaIncompatible,
    /// A uniqueness constraint rejected the operation.
    AlreadyExists,
    /// The row or entity does not exist.
    NotFound,
    /// A foreign-key or uniqueness constraint rejected the operation.
    Conflict,
    /// SQLite reported the database file is corrupted.
    Corruption,
    /// I/O on the underlying file failed.
    Transport,
    /// SQLite was busy and the busy timeout elapsed.
    Busy,
    /// Underlying resource exhaustion (memory, file descriptors).
    Resource,
    /// A catch-all for unexpected SQLite errors that do not map to a
    /// more specific category.
    Internal,
}

/// Storage-layer error.
#[derive(Debug)]
pub struct StoreError {
    kind: StoreErrorKind,
    message: String,
    correlation_id: CorrelationId,
    source: Option<String>,
}

impl StoreError {
    /// Constructs a new error with the supplied classification.
    #[must_use]
    pub fn new(
        kind: StoreErrorKind,
        message: impl Into<String>,
        correlation_id: CorrelationId,
    ) -> Self {
        Self { kind, message: message.into(), correlation_id, source: None }
    }

    /// Returns the categorical classification.
    #[must_use]
    pub const fn kind(&self) -> StoreErrorKind {
        self.kind
    }

    /// Returns the user-safe message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the correlation ID assigned to the failure.
    #[must_use]
    pub const fn correlation_id(&self) -> CorrelationId {
        self.correlation_id
    }

    /// Returns the optional sanitized source description.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Attaches a sanitized source description for diagnostics.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Maps a [`rusqlite::Error`] into a [`StoreError`] using the
    /// supplied correlation ID. The mapping is total; every
    /// `rusqlite::Error` variant maps to one [`StoreErrorKind`].
    ///
    /// SQLite reports I/O failures through `SqliteFailure` with the
    /// `SystemIoFailure` code, but `Open` failures and the
    /// `CannotOpen` code travel through the same variant. The
    /// mapping funnels every disk-level error into
    /// [`StoreErrorKind::Transport`] so the application facade can
    /// preserve the request correlation ID and surface a retryable
    /// category to clients.
    pub fn from_rusqlite(error: rusqlite::Error, correlation_id: CorrelationId) -> Self {
        let (kind, message) = match &error {
            rusqlite::Error::SqliteFailure(code, _)
                if code.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY {
                    (StoreErrorKind::Conflict, "foreign-key constraint violated")
                } else if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                    || code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                {
                    (StoreErrorKind::AlreadyExists, "uniqueness constraint violated")
                } else {
                    (StoreErrorKind::Conflict, "SQL constraint violated")
                }
            }
            rusqlite::Error::SqliteFailure(code, _)
                if code.code == rusqlite::ErrorCode::DatabaseBusy
                    || code.code == rusqlite::ErrorCode::DatabaseLocked =>
            {
                (StoreErrorKind::Busy, "database is busy")
            }
            rusqlite::Error::SqliteFailure(code, _)
                if code.code == rusqlite::ErrorCode::DatabaseCorrupt =>
            {
                (StoreErrorKind::Corruption, "database file is corrupt")
            }
            rusqlite::Error::SqliteFailure(code, _)
                if code.code == rusqlite::ErrorCode::SystemIoFailure
                    || code.code == rusqlite::ErrorCode::CannotOpen =>
            {
                (StoreErrorKind::Transport, "SQLite reported a transport-level error")
            }
            rusqlite::Error::SqliteFailure(code, _)
                if code.code == rusqlite::ErrorCode::OutOfMemory =>
            {
                (StoreErrorKind::Resource, "SQLite exhausted available memory")
            }
            rusqlite::Error::InvalidQuery
            | rusqlite::Error::InvalidParameterName(_)
            | rusqlite::Error::InvalidColumnIndex(_)
            | rusqlite::Error::InvalidColumnName(_)
            | rusqlite::Error::InvalidColumnType(_, _, _)
            | rusqlite::Error::InvalidPath(_) => {
                (StoreErrorKind::Validation, "invalid query parameter")
            }
            rusqlite::Error::IntegralValueOutOfRange(_, _)
            | rusqlite::Error::Utf8Error(_)
            | rusqlite::Error::NulError(_) => (StoreErrorKind::Validation, "value out of range"),
            rusqlite::Error::QueryReturnedNoRows => (StoreErrorKind::NotFound, "row not found"),
            rusqlite::Error::FromSqlConversionFailure(_, _, _) => {
                (StoreErrorKind::Validation, "value type mismatch")
            }
            rusqlite::Error::SqliteSingleThreadedMode
            | rusqlite::Error::StatementChangedRows(_)
            | rusqlite::Error::ExecuteReturnedResults => {
                (StoreErrorKind::Internal, "SQLite API misuse")
            }
            _ => (StoreErrorKind::Internal, "unexpected SQLite error"),
        };
        Self::new(kind, message, correlation_id).with_source(error.to_string())
    }
}

#[cfg(test)]
// Tests intentionally panic on invariant violations because the
// failure mode is "test failed", not "library panicked".
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert on fallible fixture data"
)]
mod tests {
    use super::*;

    #[test]
    fn from_rusqlite_preserves_correlation_id_for_known_variants() {
        let correlation_id = CorrelationId::new();
        let cases = [
            (rusqlite::Error::QueryReturnedNoRows, StoreErrorKind::NotFound),
            (rusqlite::Error::InvalidQuery, StoreErrorKind::Validation),
            (rusqlite::Error::InvalidColumnIndex(0), StoreErrorKind::Validation),
        ];
        for (error, expected) in cases {
            let mapped = StoreError::from_rusqlite(error, correlation_id);
            assert_eq!(mapped.kind(), expected);
            assert_eq!(mapped.correlation_id(), correlation_id);
        }
    }
}
