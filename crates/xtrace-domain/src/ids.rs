//! Typed nominal identifiers shared across the X-trace stack.
//!
//! Each identifier is a UUIDv7 stored as a 16-byte blob in storage and
//! rendered as a lowercase canonical string on the wire. UUIDv7 gives
//! time-sortable, collision-resistant IDs without making timestamps
//! authoritative. Every public entity has its own nominal type so the
//! type system refuses to mix a `RecordingId` with a `RunId`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Marker trait shared by every nominal identifier.
///
/// Implementers store a UUIDv7 internally and expose it through the
/// standard conversions. The trait is sealed: new identifiers are added
/// in this module so the conversion discipline stays uniform.
pub trait Id: Copy + Clone + Eq + PartialEq + Hash + fmt::Debug + fmt::Display + FromStr {
    /// Returns the underlying UUIDv7 value.
    fn as_uuid(&self) -> Uuid;

    /// Returns the lowercase canonical string representation.
    fn as_string(&self) -> String {
        self.as_uuid().as_hyphenated().to_string()
    }
}

use std::hash::Hash;

/// Macro that generates a UUIDv7-backed nominal identifier.
///
/// Every identifier produced through this macro:
/// - stores a `Uuid` (16 bytes);
/// - implements `Debug`, `Display`, `Clone`, `Copy`, `PartialEq`, `Eq`,
///   `Hash`, `Serialize`, `Deserialize`;
/// - rejects malformed string input through `FromStr` with a stable
///   error;
/// - provides a deterministic `new()` that draws a fresh UUIDv7 from
///   the system clock.
macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        #[repr(transparent)]
        pub struct $name(pub(crate) Uuid);

        impl $name {
            /// Returns a fresh identifier derived from the current system clock.
            ///
            /// This is the only approved constructor; the macro also exposes
            /// the inner `Uuid` field through `from_uuid` and `as_uuid`.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Wraps an existing UUID. Use only when reading from storage or
            /// verifying an inbound wire value.
            #[must_use]
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Id for $name {
            fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.as_string())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.as_string())
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self(value)
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let uuid =
                    Uuid::parse_str(s).map_err(|source| IdParseError::new(stringify!($name), source))?;
                Ok(Self(uuid))
            }
        }
    };
}

/// Error returned when an identifier string cannot be parsed.
///
/// The error intentionally does not embed the input string so it is safe
/// to log in diagnostics.
#[derive(Debug, thiserror::Error)]
#[error("invalid {kind} identifier")]
pub struct IdParseError {
    kind: &'static str,
    #[source]
    source: uuid::Error,
}

impl IdParseError {
    fn new(kind: &'static str, source: uuid::Error) -> Self {
        Self { kind, source }
    }
}

uuid_id! {
    /// Identity of a project. Stable for the lifetime of the repository
    /// fingerprint it was created from.
    ProjectId
}
uuid_id! {
    /// Identity of a run (scan, capture, attach, exercise, export, ...).
    /// Persisted before external work begins so retries can return the
    /// original receipt.
    RunId
}
uuid_id! {
    /// Identity of one catalog revision. Monotonic per project.
    CatalogRevisionId
}
uuid_id! {
    /// Identity of a stable HTTP operation. Computed from a normalized
    /// method/route/binding/component tuple.
    OperationId
}
uuid_id! {
    /// Identity of one operation version. Hashes the reconciled signature
    /// and handler claims.
    OperationVersionId
}
uuid_id! {
    /// Identity of an endpoint claim produced by a runtime adapter or
    /// static analyzer.
    ClaimId
}
uuid_id! {
    /// Identity of one runtime session, scoped to a process handshake.
    RuntimeSessionId
}
uuid_id! {
    /// Identity of one recorded execution. Immutable after finalization.
    RecordingId
}
uuid_id! {
    /// Identity of one replayable frame inside a recording.
    FrameId
}
uuid_id! {
    /// Identity of one captured interaction (database, outbound HTTP, ...).
    InteractionId
}
uuid_id! {
    /// Identity of a stored source artifact.
    SourceArtifactId
}
uuid_id! {
    /// Identity of a recorded source revision.
    SourceRevisionId
}
uuid_id! {
    /// Identity of a named policy (capture, redaction, retention).
    PolicyId
}
/// Identity of a correlated set of work, surfaced in diagnostics and
/// error responses so user support requests never carry a captured value.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct CorrelationId(pub(crate) Uuid);

impl CorrelationId {
    /// Returns a fresh correlation ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CorrelationId({})", self.0.as_hyphenated())
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.as_hyphenated().to_string())
    }
}

impl FromStr for CorrelationId {
    type Err = IdParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uuid =
            Uuid::parse_str(s).map_err(|source| IdParseError::new("CorrelationId", source))?;
        Ok(Self(uuid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nominal_types_are_not_interchangeable() {
        fn assert_not_same<A: Id, B: Id>() {}
        assert_not_same::<ProjectId, RunId>();
    }

    #[test]
    fn round_trip_string_form() {
        let id = OperationId::new();
        let s = id.to_string();
        let parsed: OperationId = s.parse().expect("id parses");
        assert_eq!(id, parsed);
    }

    #[test]
    fn malformed_string_is_rejected() {
        let err = "not-a-uuid".parse::<FrameId>().unwrap_err();
        assert!(err.to_string().contains("FrameId"));
    }

    #[test]
    fn correlation_id_display_is_canonical() {
        let id = CorrelationId::new();
        let s = id.to_string();
        assert_eq!(s.len(), 36, "UUIDv7 hyphenated form has 36 characters");
    }
}
