//! Internal error type used by application ports.
//!
//! Every port method returns a [`PortError`]. The [`Application`]
//! facade converts each variant into the corresponding public
//! [`AppError`] before the value crosses a boundary. This keeps
//! domain rules and transport details confined to their respective
//! layers.
//!
//! [`Application`]: crate::application::Application

use xtrace_domain::CorrelationId;

/// Categorical view of an internal port failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PortErrorKind {
    /// Validation failed before any work was attempted.
    Validation,
    /// A unique entity was requested but already exists.
    AlreadyExists,
    /// A unique entity was requested but does not exist.
    NotFound,
    /// Storage layer reported a concurrency conflict.
    Conflict,
    /// Storage layer rejected the request due to schema compatibility.
    Compatibility,
    /// Storage layer is exhausted or unavailable.
    Resource,
    /// Storage layer reports the underlying SQLite database is corrupt.
    Corruption,
    /// Storage layer reports a transport-level I/O failure.
    Transport,
    /// An unexpected internal failure occurred in the port.
    Internal,
}

/// Internal error returned by port implementations.
///
/// `kind` is the categorical classification; `message` is sanitized
/// and safe to surface to clients; `source` is preserved as a string
/// so diagnostics can include the underlying cause without exposing
/// captured values or secrets.
#[derive(Clone, Debug)]
pub struct PortError {
    kind: PortErrorKind,
    message: String,
    correlation_id: CorrelationId,
    source: Option<String>,
}

impl PortError {
    /// Constructs a new port error with the supplied classification
    /// and message. Use [`PortError::with_source`] to attach the
    /// underlying cause for diagnostics.
    #[must_use]
    pub fn new(
        kind: PortErrorKind,
        message: impl Into<String>,
        correlation_id: CorrelationId,
    ) -> Self {
        Self { kind, message: message.into(), correlation_id, source: None }
    }

    /// Returns the categorical classification.
    #[must_use]
    pub const fn kind(&self) -> PortErrorKind {
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
}
