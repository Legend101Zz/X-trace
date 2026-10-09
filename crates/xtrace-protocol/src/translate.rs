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

use xtrace_domain::{
    AppError, BindingRole, CorrelationId, DropReason, ErrorCategory, ErrorCode, Gap, GapReason,
    MonotonicNs, NameOrigin, OutcomeException, OutcomeKind, RecordingOutcome, RetryAdvice,
    SourceBinding, UnavailableReason,
};

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

/// Maps a wire `SourceBinding` value. `UNSPECIFIED` (0) is a valid "no facts" binding; an unknown
/// number returns `None` and ingest rejects it rather than coercing it.
#[must_use]
pub fn source_binding_from_wire(raw: i32) -> Option<SourceBinding> {
    Some(match wire::SourceBinding::try_from(raw).ok()? {
        wire::SourceBinding::Unspecified => SourceBinding::Unspecified,
        wire::SourceBinding::Verified => SourceBinding::Verified,
        wire::SourceBinding::AttestationMissing => SourceBinding::AttestationMissing,
        wire::SourceBinding::ClassBytesMismatch => SourceBinding::ClassBytesMismatch,
        wire::SourceBinding::DebugMetadataAbsent => SourceBinding::DebugMetadataAbsent,
        wire::SourceBinding::SourceMetadataInvalid => SourceBinding::SourceMetadataInvalid,
        wire::SourceBinding::ObservedUnattested => SourceBinding::ObservedUnattested,
        wire::SourceBinding::SourceMapAbsent => SourceBinding::SourceMapAbsent,
        wire::SourceBinding::SourceMapUnresolved => SourceBinding::SourceMapUnresolved,
    })
}

/// Maps a domain `SourceBinding` to its wire number.
#[must_use]
pub const fn source_binding_to_wire(binding: SourceBinding) -> i32 {
    (match binding {
        SourceBinding::Unspecified => wire::SourceBinding::Unspecified,
        SourceBinding::Verified => wire::SourceBinding::Verified,
        SourceBinding::AttestationMissing => wire::SourceBinding::AttestationMissing,
        SourceBinding::ClassBytesMismatch => wire::SourceBinding::ClassBytesMismatch,
        SourceBinding::DebugMetadataAbsent => wire::SourceBinding::DebugMetadataAbsent,
        SourceBinding::SourceMetadataInvalid => wire::SourceBinding::SourceMetadataInvalid,
        SourceBinding::ObservedUnattested => wire::SourceBinding::ObservedUnattested,
        SourceBinding::SourceMapAbsent => wire::SourceBinding::SourceMapAbsent,
        SourceBinding::SourceMapUnresolved => wire::SourceBinding::SourceMapUnresolved,
    }) as i32
}

/// Maps a wire `UnavailableReason`; `None` for unspecified or unknown values.
#[must_use]
pub fn unavailable_reason_from_wire(raw: i32) -> Option<UnavailableReason> {
    match wire::UnavailableReason::try_from(raw).ok()? {
        wire::UnavailableReason::Unspecified => None,
        wire::UnavailableReason::CapabilityUnsupported => {
            Some(UnavailableReason::CapabilityUnsupported)
        }
        wire::UnavailableReason::DebugMetadataAbsent => {
            Some(UnavailableReason::DebugMetadataAbsent)
        }
        wire::UnavailableReason::CaptureBudgetExhausted => {
            Some(UnavailableReason::CaptureBudgetExhausted)
        }
        wire::UnavailableReason::SourceArtifactMissing => {
            Some(UnavailableReason::SourceArtifactMissing)
        }
        wire::UnavailableReason::RecorderDisconnected => {
            Some(UnavailableReason::RecorderDisconnected)
        }
        wire::UnavailableReason::FocusedCaptureNotArmed => {
            Some(UnavailableReason::FocusedCaptureNotArmed)
        }
        wire::UnavailableReason::UnsafeToRender => Some(UnavailableReason::UnsafeToRender),
        wire::UnavailableReason::ClassNotTransformable => {
            Some(UnavailableReason::ClassNotTransformable)
        }
    }
}

/// Maps a domain `UnavailableReason` to its wire number. The internal
/// `PrivacyPolicyUnavailable` has no wire counterpart and returns `None`.
#[must_use]
pub const fn unavailable_reason_to_wire(reason: UnavailableReason) -> Option<i32> {
    Some(
        (match reason {
            UnavailableReason::CapabilityUnsupported => {
                wire::UnavailableReason::CapabilityUnsupported
            }
            UnavailableReason::DebugMetadataAbsent => wire::UnavailableReason::DebugMetadataAbsent,
            UnavailableReason::CaptureBudgetExhausted => {
                wire::UnavailableReason::CaptureBudgetExhausted
            }
            UnavailableReason::SourceArtifactMissing => {
                wire::UnavailableReason::SourceArtifactMissing
            }
            UnavailableReason::RecorderDisconnected => {
                wire::UnavailableReason::RecorderDisconnected
            }
            UnavailableReason::PrivacyPolicyUnavailable => return None,
            UnavailableReason::FocusedCaptureNotArmed => {
                wire::UnavailableReason::FocusedCaptureNotArmed
            }
            UnavailableReason::UnsafeToRender => wire::UnavailableReason::UnsafeToRender,
            UnavailableReason::ClassNotTransformable => {
                wire::UnavailableReason::ClassNotTransformable
            }
        }) as i32,
    )
}

/// Maps a wire `DropReason`; `None` for unspecified or unknown values.
#[must_use]
pub fn drop_reason_from_wire(raw: i32) -> Option<DropReason> {
    match wire::DropReason::try_from(raw).ok()? {
        wire::DropReason::Unspecified => None,
        wire::DropReason::BackpressureShed => Some(DropReason::BackpressureShed),
        wire::DropReason::QueueFull => Some(DropReason::QueueFull),
        wire::DropReason::SequenceGap => Some(DropReason::SequenceGap),
        wire::DropReason::AdapterDropped => Some(DropReason::AdapterDropped),
        wire::DropReason::ThrottleSuppressed => Some(DropReason::ThrottleSuppressed),
        wire::DropReason::LineBudget => Some(DropReason::LineBudget),
        wire::DropReason::ValueBudget => Some(DropReason::ValueBudget),
    }
}

/// Maps a domain `DropReason` to its wire number.
#[must_use]
pub const fn drop_reason_to_wire(reason: DropReason) -> i32 {
    (match reason {
        DropReason::BackpressureShed => wire::DropReason::BackpressureShed,
        DropReason::QueueFull => wire::DropReason::QueueFull,
        DropReason::SequenceGap => wire::DropReason::SequenceGap,
        DropReason::AdapterDropped => wire::DropReason::AdapterDropped,
        DropReason::ThrottleSuppressed => wire::DropReason::ThrottleSuppressed,
        DropReason::LineBudget => wire::DropReason::LineBudget,
        DropReason::ValueBudget => wire::DropReason::ValueBudget,
    }) as i32
}

/// Maps a wire `BindingRole`; `None` for unspecified or unknown values.
#[must_use]
pub fn binding_role_from_wire(raw: i32) -> Option<BindingRole> {
    match wire::BindingRole::try_from(raw).ok()? {
        wire::BindingRole::Unspecified => None,
        wire::BindingRole::Argument => Some(BindingRole::Argument),
        wire::BindingRole::Return => Some(BindingRole::Return),
        wire::BindingRole::Local => Some(BindingRole::Local),
        wire::BindingRole::Exception => Some(BindingRole::Exception),
        wire::BindingRole::Receiver => Some(BindingRole::Receiver),
    }
}

/// Maps a wire `NameOrigin`; `None` for unspecified or unknown values.
#[must_use]
pub fn name_origin_from_wire(raw: i32) -> Option<NameOrigin> {
    match wire::NameOrigin::try_from(raw).ok()? {
        wire::NameOrigin::Unspecified => None,
        wire::NameOrigin::Declared => Some(NameOrigin::Declared),
        wire::NameOrigin::Synthesized => Some(NameOrigin::Synthesized),
    }
}

/// Maps a wire `GapReason`; `None` for unspecified or unknown values.
#[must_use]
pub fn gap_reason_from_wire(raw: i32) -> Option<GapReason> {
    match wire::GapReason::try_from(raw).ok()? {
        wire::GapReason::Unspecified => None,
        wire::GapReason::LineBudget => Some(GapReason::LineBudget),
        wire::GapReason::ValueBudget => Some(GapReason::ValueBudget),
        wire::GapReason::Throttle => Some(GapReason::Throttle),
        wire::GapReason::QueueFull => Some(GapReason::QueueFull),
        wire::GapReason::CorrelationLost => Some(GapReason::CorrelationLost),
        wire::GapReason::ClassNotTransformed => Some(GapReason::ClassNotTransformed),
        wire::GapReason::ModuleLoadedBeforeArm => Some(GapReason::ModuleLoadedBeforeArm),
        wire::GapReason::SourceMapAbsent => Some(GapReason::SourceMapAbsent),
        wire::GapReason::HandledExceptionUnobserved => Some(GapReason::HandledExceptionUnobserved),
        wire::GapReason::ChildProcessNotInstrumented => {
            Some(GapReason::ChildProcessNotInstrumented)
        }
        wire::GapReason::BootstrapConsumed => Some(GapReason::BootstrapConsumed),
    }
}

/// Maps a wire `OutcomeKind`; `None` for unspecified or unknown values.
#[must_use]
pub fn outcome_kind_from_wire(raw: i32) -> Option<OutcomeKind> {
    match wire::OutcomeKind::try_from(raw).ok()? {
        wire::OutcomeKind::Unspecified => None,
        wire::OutcomeKind::Responded => Some(OutcomeKind::Responded),
        wire::OutcomeKind::ExceptionPropagated => Some(OutcomeKind::ExceptionPropagated),
        wire::OutcomeKind::ClientAborted => Some(OutcomeKind::ClientAborted),
        wire::OutcomeKind::Unobserved => Some(OutcomeKind::Unobserved),
    }
}

/// Translates a wire `GapPayload` into a domain [`Gap`], enforcing the payload rules (known
/// reason, positive count, ordered sequence range).
///
/// # Errors
///
/// Returns a stable reason string naming the first violated rule.
pub fn gap_from_wire(gap: &wire::GapPayload) -> Result<Gap, &'static str> {
    let reason = gap_reason_from_wire(gap.reason).ok_or("gap_reason_unknown")?;
    if gap.count == 0 {
        return Err("gap_count_zero");
    }
    if gap.first_recording_seq > gap.last_recording_seq {
        return Err("gap_sequence_range_inverted");
    }
    Ok(Gap {
        reason,
        count: gap.count,
        first_seq: gap.first_recording_seq,
        last_seq: gap.last_recording_seq,
    })
}

/// Translates a wire `RecordingOutcome` into the domain type and validates it. Wire status 0 maps
/// to `None`; 100..=599 to `Some`; anything else is invalid.
///
/// # Errors
///
/// Returns a stable reason string naming the first violated rule.
pub fn outcome_from_wire(
    outcome: &wire::RecordingOutcome,
) -> Result<RecordingOutcome, &'static str> {
    let kind = outcome_kind_from_wire(outcome.kind).ok_or("outcome_kind_unknown")?;
    let http_status = match outcome.http_status {
        0 => None,
        100..=599 => {
            Some(u16::try_from(outcome.http_status).map_err(|_| "http_status_out_of_range")?)
        }
        _ => return Err("http_status_out_of_range"),
    };
    let result = RecordingOutcome {
        kind,
        http_status,
        exception: outcome.exception.as_ref().map(|e| OutcomeException {
            exception_type: e.exception_type.clone(),
            message: e.sanitized_message.clone(),
        }),
        thrown_from_event_id: if outcome.thrown_from_event_id.is_empty() {
            None
        } else {
            Some(outcome.thrown_from_event_id.clone())
        },
    };
    result.validate()?;
    Ok(result)
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
    #[test]
    fn every_wire_enum_value_round_trips_or_is_explicitly_unmapped() {
        for raw in 0..16 {
            if let Some(binding) = source_binding_from_wire(raw) {
                assert_eq!(source_binding_to_wire(binding), raw);
            }
            if let Some(reason) = unavailable_reason_from_wire(raw) {
                assert_eq!(unavailable_reason_to_wire(reason), Some(raw));
            }
            if let Some(reason) = drop_reason_from_wire(raw) {
                assert_eq!(drop_reason_to_wire(reason), raw);
            }
        }
        assert_eq!(source_binding_from_wire(8), Some(SourceBinding::SourceMapUnresolved));
        assert_eq!(source_binding_from_wire(9), None, "unknown values are not coerced");
        assert_eq!(unavailable_reason_from_wire(8), Some(UnavailableReason::ClassNotTransformable));
        assert_eq!(unavailable_reason_from_wire(0), None);
        assert_eq!(unavailable_reason_to_wire(UnavailableReason::PrivacyPolicyUnavailable), None);
        assert_eq!(drop_reason_from_wire(7), Some(DropReason::ValueBudget));
        assert_eq!(drop_reason_from_wire(8), None);
    }

    #[test]
    fn gap_reason_role_origin_and_outcome_kind_cover_the_wire_values() {
        assert_eq!(gap_reason_from_wire(1), Some(GapReason::LineBudget));
        assert_eq!(gap_reason_from_wire(11), Some(GapReason::BootstrapConsumed));
        assert_eq!(gap_reason_from_wire(12), None);
        assert_eq!(gap_reason_from_wire(0), None);
        for raw in 1..=11 {
            assert!(gap_reason_from_wire(raw).is_some(), "gap reason {raw}");
        }
        for raw in 1..=5 {
            assert!(binding_role_from_wire(raw).is_some(), "role {raw}");
        }
        assert_eq!(binding_role_from_wire(6), None);
        assert_eq!(name_origin_from_wire(2), Some(NameOrigin::Synthesized));
        assert_eq!(name_origin_from_wire(3), None);
        for raw in 1..=4 {
            assert!(outcome_kind_from_wire(raw).is_some(), "outcome {raw}");
        }
        assert_eq!(outcome_kind_from_wire(5), None);
    }

    #[test]
    fn gap_payload_translation_enforces_rules() {
        let ok = wire::GapPayload {
            reason: wire::GapReason::LineBudget as i32,
            count: 7,
            first_recording_seq: 5,
            last_recording_seq: 11,
        };
        let gap = gap_from_wire(&ok).unwrap();
        assert_eq!(
            (gap.reason, gap.count, gap.first_seq, gap.last_seq),
            (GapReason::LineBudget, 7, 5, 11)
        );
        assert_eq!(gap_from_wire(&wire::GapPayload { count: 0, ..ok }), Err("gap_count_zero"));
        assert_eq!(gap_from_wire(&wire::GapPayload { reason: 0, ..ok }), Err("gap_reason_unknown"));
        assert_eq!(
            gap_from_wire(&wire::GapPayload { first_recording_seq: 12, ..ok }),
            Err("gap_sequence_range_inverted")
        );
        let unknown = wire::GapPayload { first_recording_seq: 0, last_recording_seq: 0, ..ok };
        assert!(gap_from_wire(&unknown).is_ok(), "0/0 means the range is unknown");
    }

    #[test]
    fn outcome_translation_maps_status_zero_to_none() {
        let responded = wire::RecordingOutcome {
            kind: wire::OutcomeKind::Responded as i32,
            http_status: 0,
            ..wire::RecordingOutcome::default()
        };
        assert_eq!(outcome_from_wire(&responded).unwrap().http_status, None);
        let ok = wire::RecordingOutcome { http_status: 404, ..responded.clone() };
        assert_eq!(outcome_from_wire(&ok).unwrap().http_status, Some(404));
        for bad in [99, 600, 70_000] {
            let r = wire::RecordingOutcome { http_status: bad, ..responded.clone() };
            assert_eq!(outcome_from_wire(&r), Err("http_status_out_of_range"), "{bad}");
        }
        let exc = wire::RecordingOutcome {
            kind: wire::OutcomeKind::ExceptionPropagated as i32,
            ..wire::RecordingOutcome::default()
        };
        assert_eq!(outcome_from_wire(&exc), Err("exception_presence_mismatch"));
        let unspecified = wire::RecordingOutcome::default();
        assert_eq!(outcome_from_wire(&unspecified), Err("outcome_kind_unknown"));
    }
}
