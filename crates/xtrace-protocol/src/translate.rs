//! Translation between generated XTP wire types and domain DTOs.
//!
//! The domain never imports anything from [`crate::generated`]. Every
//! wire value that has a typed domain equivalent is converted here so
//! validation and conversion errors stay confined to the protocol
//! layer. Functions are total where possible and return a typed error
//! otherwise; callers must never panic on a malformed payload.
//!
//! Slice 1A keeps the translation surface intentionally small. Each
//! future payload variant that earns a domain DTO adds a function
//! here without disturbing the existing ones.

use std::convert::TryFrom;

use xtrace_domain::{AppError, CorrelationId, ErrorCategory, ErrorCode, MonotonicNs, RetryAdvice};

use crate::envelope::EnvelopeError;
use crate::generated::agent as wire;

/// Domain-side view of a transport-level health message.
///
/// Adapter health is informational; consumers must not derive
/// security-sensitive decisions from a single health reading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthSnapshot {
    /// Adapter monotonic nanoseconds at send time.
    pub monotonic_ns: MonotonicNs,
    /// Reported adapter queue depth in batches.
    pub queue_depth_batches: u32,
    /// Adapter-reported resident memory in bytes.
    pub resident_bytes: u64,
    /// Optional free-form status string supplied by the adapter.
    pub status: Option<String>,
}

impl HealthSnapshot {
    /// Translates the wire [`wire::Health`] message into a domain
    /// [`HealthSnapshot`].
    ///
    /// The wire representation is permissive (status may be absent);
    /// the domain shape is total once constructed. The conversion
    /// performs no I/O and never panics.
    #[must_use]
    pub fn from_wire(health: &wire::Health) -> Self {
        Self {
            monotonic_ns: MonotonicNs::from_raw(health.monotonic_ns),
            queue_depth_batches: health.queue_depth_batches,
            resident_bytes: health.resident_bytes,
            status: if health.status.is_empty() { None } else { Some(health.status.clone()) },
        }
    }

    /// Renders the snapshot back into a wire [`wire::Health`] message.
    #[must_use]
    pub fn into_wire(&self) -> wire::Health {
        wire::Health {
            monotonic_ns: self.monotonic_ns.0,
            queue_depth_batches: self.queue_depth_batches,
            resident_bytes: self.resident_bytes,
            status: self.status.clone().unwrap_or_default(),
        }
    }
}

impl TryFrom<&wire::Health> for HealthSnapshot {
    type Error = AppError;
    fn try_from(health: &wire::Health) -> Result<Self, Self::Error> {
        // Health has no field-level constraints today; the conversion
        // is infallible. The `TryFrom` plumbing is kept so adding
        // constraints later does not break callers.
        Ok(Self::from_wire(health))
    }
}

/// Translates an envelope decode error into a public [`AppError`].
#[must_use]
pub fn envelope_error_to_app_error(
    error: &EnvelopeError,
    correlation_id: CorrelationId,
) -> AppError {
    let code = ErrorCode::new("XTR-PROTOCOL-DECODE");
    match error {
        EnvelopeError::TooLarge { size, limit } => AppError::new(
            code,
            ErrorCategory::Validation,
            "envelope exceeds negotiated size limit",
            RetryAdvice::None,
            correlation_id,
        )
        .with_detail("size", i64::try_from(*size).unwrap_or(i64::MAX))
        .with_detail("limit", i64::from(*limit)),
        EnvelopeError::Truncated { got } => AppError::new(
            code,
            ErrorCategory::Transport,
            "envelope stream ended before a full envelope arrived",
            RetryAdvice::Immediate,
            correlation_id,
        )
        .with_detail("bytes", i64::try_from(*got).unwrap_or(i64::MAX)),
        EnvelopeError::BadMagic => AppError::new(
            code,
            ErrorCategory::Compatibility,
            "wire magic prefix is not XTP1",
            RetryAdvice::None,
            correlation_id,
        ),
        EnvelopeError::BadLength(value) => AppError::new(
            code,
            ErrorCategory::Validation,
            "envelope length prefix is not representable",
            RetryAdvice::None,
            correlation_id,
        )
        .with_detail("length", i64::from(*value)),
        EnvelopeError::ProtocolVersion { got_major, got_minor, expected_major, max_minor } => {
            AppError::new(
                code,
                ErrorCategory::Compatibility,
                "protocol version is outside the negotiated range",
                RetryAdvice::None,
                correlation_id,
            )
            .with_detail("got_major", i64::from(*got_major))
            .with_detail("got_minor", i64::from(*got_minor))
            .with_detail("expected_major", i64::from(*expected_major))
            .with_detail("max_minor", i64::from(*max_minor))
        }
        EnvelopeError::Decode(_) => AppError::new(
            code,
            ErrorCategory::Validation,
            "envelope bytes are not a valid protobuf message",
            RetryAdvice::None,
            correlation_id,
        ),
        EnvelopeError::Encode(_) => AppError::new(
            code,
            ErrorCategory::Internal,
            "envelope encode failed",
            RetryAdvice::None,
            correlation_id,
        ),
        EnvelopeError::Io(_) => AppError::new(
            code,
            ErrorCategory::Transport,
            "envelope I/O failed",
            RetryAdvice::Immediate,
            correlation_id,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_translation_round_trips_known_fields() {
        let wire_health = wire::Health {
            monotonic_ns: 12_345,
            queue_depth_batches: 4,
            resident_bytes: 1024,
            status: "ok".to_string(),
        };
        let snapshot = HealthSnapshot::from_wire(&wire_health);
        assert_eq!(snapshot.monotonic_ns.0, 12_345);
        assert_eq!(snapshot.queue_depth_batches, 4);
        assert_eq!(snapshot.resident_bytes, 1024);
        assert_eq!(snapshot.status.as_deref(), Some("ok"));

        let back = snapshot.into_wire();
        assert_eq!(back.monotonic_ns, wire_health.monotonic_ns);
        assert_eq!(back.status, wire_health.status);
    }

    #[test]
    fn health_translation_collapses_empty_status() {
        let wire_health = wire::Health {
            monotonic_ns: 0,
            queue_depth_batches: 0,
            resident_bytes: 0,
            status: String::new(),
        };
        let snapshot = HealthSnapshot::from_wire(&wire_health);
        assert!(snapshot.status.is_none());
    }
}
