//! Public error contract.
//!
//! Every public error in X-trace carries a stable code, a coarse
//! category, a user-safe message, retry guidance, optional remediation
//! hints, and a correlation ID. Internal layers retain their own typed
//! errors but must translate into [`AppError`] before crossing a port
//! boundary.
//!
//! The shape of this struct mirrors `03-program-design.md` §7. Capture
//! details are restricted to scalar fields so diagnostics never embed a
//! raw captured value.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ids::CorrelationId;

/// Stable, user-visible error code.
///
/// New codes require an ADR. The reverse-DNS prefix is intentionally
/// avoided in favor of the `XTR-*` vocabulary documented in Gate 3.
///
/// Codes are owned strings so they can flow through the deserializer
/// without borrowing from input bytes. The `codes` module exposes
/// lazily-initialized singletons for the standard vocabulary.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ErrorCode(String);

impl ErrorCode {
    /// Constructs an error code from a checked string literal.
    #[must_use]
    pub fn new(code: impl Into<String>) -> Self {
        Self(code.into())
    }

    /// Returns the code as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&'static str> for ErrorCode {
    fn from(value: &'static str) -> Self {
        Self(value.to_string())
    }
}

/// Coarse error category used by clients for retry decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    /// Input failed schema or semantic validation.
    Validation,
    /// Referenced entity is missing.
    NotFound,
    /// Concurrency or version conflict.
    Conflict,
    /// Boundary compatibility issue (protocol major, store version).
    Compatibility,
    /// Caller is not permitted to perform the action.
    Permission,
    /// Project policy forbids the action.
    Policy,
    /// Resource exhaustion (disk, memory, queue).
    Resource,
    /// Transport failure (network, pipe, file).
    Transport,
    /// Persistent storage is corrupted.
    Corruption,
    /// Unexpected internal failure.
    Internal,
    /// Operation was cancelled.
    Cancelled,
}

impl ErrorCategory {
    /// Returns the wire string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validation => "validation",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Compatibility => "compatibility",
            Self::Permission => "permission",
            Self::Policy => "policy",
            Self::Resource => "resource",
            Self::Transport => "transport",
            Self::Corruption => "corruption",
            Self::Internal => "internal",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Retry advice surfaced to clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryAdvice {
    /// Retry the same request immediately.
    Immediate,
    /// Retry after the suggested delay.
    AfterDelay {
        /// Suggested wait before retrying.
        millis: u32,
    },
    /// Retry once the operator restarts the process.
    AfterRestart,
    /// Do not retry; the request is final.
    None,
    /// Retry only after the user changes configuration.
    AfterUserAction,
}

impl RetryAdvice {
    /// Returns the wire string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Immediate => "immediate",
            Self::AfterDelay { .. } => "after_delay",
            Self::AfterRestart => "after_restart",
            Self::None => "none",
            Self::AfterUserAction => "after_user_action",
        }
    }
}

/// Scalar detail carried alongside an error.
///
/// Restricted to types that cannot smuggle a captured value into
/// diagnostics. Internal layers needing richer details must convert to
/// a structured payload before crossing the port.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SafeScalar {
    /// Boolean.
    Bool(bool),
    /// Integer.
    Integer(i64),
    /// Floating-point value.
    Float(f64),
    /// String.
    String(String),
}

impl From<&'static str> for SafeScalar {
    fn from(value: &'static str) -> Self {
        Self::String(value.to_string())
    }
}

impl From<bool> for SafeScalar {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for SafeScalar {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<String> for SafeScalar {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

/// Remediation hint attached to an error.
///
/// `command_ref` references a documented command template so the UI
/// never renders arbitrary user input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Remediation {
    /// Stable kind (`command`, `config`, `manual`).
    pub kind: String,
    /// User-visible label.
    pub label: String,
    /// Optional reference to a documented command template.
    pub command_ref: Option<String>,
}

/// Public error returned across every port in X-trace.
///
/// Captured values and secret material must never be formatted into
/// any field of this struct. The `details` map accepts only
/// [`SafeScalar`] values so diagnostics stay sanitized by construction.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppError {
    /// Stable error code.
    pub code: ErrorCode,
    /// Coarse category.
    pub category: ErrorCategory,
    /// User-safe message.
    pub message: String,
    /// Retry advice.
    pub retry: RetryAdvice,
    /// Optional remediation hints.
    pub remediation: Vec<Remediation>,
    /// Correlation ID surfaced to the user.
    pub correlation_id: CorrelationId,
    /// Sanitized scalar details.
    pub details: BTreeMap<String, SafeScalar>,
}

impl AppError {
    /// Constructs a new error with mandatory fields and no remediation.
    #[must_use]
    pub fn new(
        code: ErrorCode,
        category: ErrorCategory,
        message: impl Into<String>,
        retry: RetryAdvice,
        correlation_id: CorrelationId,
    ) -> Self {
        Self {
            code,
            category,
            message: message.into(),
            retry,
            remediation: Vec::new(),
            correlation_id,
            details: BTreeMap::new(),
        }
    }

    /// Adds a remediation hint.
    #[must_use]
    pub fn with_remediation(mut self, hint: Remediation) -> Self {
        self.remediation.push(hint);
        self
    }

    /// Adds a sanitized scalar detail.
    #[must_use]
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<SafeScalar>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}

/// Standard error codes used across the spine. Codes for downstream
/// features are added next to the code that raises them.
///
/// The codes are exposed as lazily initialized singletons so callers can
/// compare against `*codes::PROJECT_NOT_FOUND` without paying a runtime
/// initialization cost on every match.
pub mod codes {
    use std::sync::LazyLock;

    use super::ErrorCode;

    /// Project identity conflict (e.g. init over an existing project).
    pub static PROJECT_ALREADY_EXISTS: LazyLock<ErrorCode> =
        LazyLock::new(|| ErrorCode::new("XTR-PROJECT-EXISTS"));
    /// Project identity missing.
    pub static PROJECT_NOT_FOUND: LazyLock<ErrorCode> =
        LazyLock::new(|| ErrorCode::new("XTR-PROJECT-NOT-FOUND"));
    /// Repository fingerprint mismatch.
    pub static PROJECT_FINGERPRINT_MISMATCH: LazyLock<ErrorCode> =
        LazyLock::new(|| ErrorCode::new("XTR-PROJECT-FINGERPRINT-MISMATCH"));

    /// Idempotency key reused with different input.
    pub static COMMAND_IDEMPOTENCY_CONFLICT: LazyLock<ErrorCode> =
        LazyLock::new(|| ErrorCode::new("XTR-COMMAND-409"));

    /// Stored schema is newer than this binary supports.
    pub static STORE_SCHEMA_NEWER: LazyLock<ErrorCode> =
        LazyLock::new(|| ErrorCode::new("XTR-STORE-NEWER"));
    /// Stored schema is older than this binary supports and no
    /// migration path is available.
    pub static STORE_SCHEMA_OLDER: LazyLock<ErrorCode> =
        LazyLock::new(|| ErrorCode::new("XTR-STORE-OLDER"));
    /// Store integrity check failed.
    pub static STORE_INTEGRITY: LazyLock<ErrorCode> =
        LazyLock::new(|| ErrorCode::new("XTR-STORE-INTEGRITY"));

    /// Protocol major version mismatch.
    pub static ADAPTER_PROTOCOL_MAJOR: LazyLock<ErrorCode> =
        LazyLock::new(|| ErrorCode::new("XTR-ADAPTER-PROTOCOL-MAJOR"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_construction_is_strict() {
        let err = AppError::new(
            codes::PROJECT_NOT_FOUND.clone(),
            ErrorCategory::NotFound,
            "no project at /tmp/repo",
            RetryAdvice::None,
            CorrelationId::new(),
        )
        .with_detail("path", "/tmp/repo");
        assert_eq!(err.code, *codes::PROJECT_NOT_FOUND);
        assert_eq!(err.details.get("path").unwrap(), &SafeScalar::String("/tmp/repo".into()));
    }

    #[test]
    fn stable_codes_have_xtr_prefix() {
        assert!(codes::PROJECT_NOT_FOUND.as_str().starts_with("XTR-"));
        assert!(codes::STORE_INTEGRITY.as_str().starts_with("XTR-"));
    }
}
