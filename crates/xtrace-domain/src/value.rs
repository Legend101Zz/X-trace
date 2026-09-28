//! Recorded value vocabulary.
//!
//! Every value that crosses the X-trace boundary enters as one of the
//! variants in [`CapturedValue`]. Empty and unknown are never conflated:
//! redacted, truncated, unavailable, and dropped each have their own
//! representation so the UI can show honest evidence.
//!
//! [`SafePreview`] is the only string a UI ever sees from a value; it is
//! constructed exclusively through this module so redaction and budget
//! enforcement happen before any data leaves the producer.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash::ContentHash;

/// Reason a value could not be captured for reasons unrelated to
/// privacy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    /// The adapter never negotiated the required capability.
    CapabilityUnsupported,
    /// Build metadata is missing for the requested detail.
    DebugMetadataAbsent,
    /// Capture budget was exhausted before the value was sampled.
    CaptureBudgetExhausted,
    /// Source artifact is missing on disk.
    SourceArtifactMissing,
    /// Recorder disconnected before sampling completed.
    RecorderDisconnected,
}

impl UnavailableReason {
    /// Returns the wire string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CapabilityUnsupported => "capability_unsupported",
            Self::DebugMetadataAbsent => "debug_metadata_absent",
            Self::CaptureBudgetExhausted => "capture_budget_exhausted",
            Self::SourceArtifactMissing => "source_artifact_missing",
            Self::RecorderDisconnected => "recorder_disconnected",
        }
    }
}

impl fmt::Display for UnavailableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reason a value was dropped before durability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DropReason {
    /// Daemon shed the event under priority-based backpressure.
    BackpressureShed,
    /// Recorder queue was full when the producer attempted to enqueue.
    QueueFull,
    /// Sequence gap rendered the value unrecoverable.
    SequenceGap,
    /// Adapter explicitly reported a drop.
    AdapterDropped,
}

impl DropReason {
    /// Returns the wire string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BackpressureShed => "backpressure_shed",
            Self::QueueFull => "queue_full",
            Self::SequenceGap => "sequence_gap",
            Self::AdapterDropped => "adapter_dropped",
        }
    }
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Coarse shape classification used to render values without revealing
/// raw payloads. This is intentionally not a recursive type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueShape {
    /// A single string scalar.
    String,
    /// A boolean.
    Boolean,
    /// A signed integer of the indicated bit width.
    Integer {
        /// Bit width of the integer (8, 16, 32, 64).
        bits: u8,
    },
    /// An IEEE 754 float of the indicated bit width.
    Float {
        /// Bit width of the float (32 or 64).
        bits: u8,
    },
    /// A null value.
    Null,
    /// A binary blob (bytes).
    Bytes,
    /// A list of values.
    List {
        /// Captured list length (post-truncation).
        length: u32,
    },
    /// A key/value object.
    Object {
        /// Captured object entry count (post-truncation).
        entries: u32,
    },
    /// Shape could not be classified.
    Unknown,
}

impl ValueShape {
    /// Returns a privacy-safe label for the shape.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Boolean => "boolean",
            Self::Integer { .. } => "integer",
            Self::Float { .. } => "float",
            Self::Null => "null",
            Self::Bytes => "bytes",
            Self::List { .. } => "list",
            Self::Object { .. } => "object",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for ValueShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A redacted, budgeted preview suitable for surfacing in the UI.
///
/// `SafePreview` cannot be constructed outside this module; producers
/// must pass through the redaction pipeline exposed in
/// `xtrace-application`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SafePreview(String);

impl SafePreview {
    /// Returns the preview as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the rendered preview length in characters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.chars().count()
    }

    /// Returns `true` if the preview is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Constructs a `SafePreview` from a string that has already been
    /// through the privacy pipeline. Crates outside this module must
    /// not call this.
    #[doc(hidden)]
    #[must_use]
    pub fn from_redacted_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl fmt::Debug for SafePreview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SafePreview({:?})", self.0)
    }
}

impl fmt::Display for SafePreview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Recorded value with explicit capture state.
///
/// Every variant carries enough information for the UI to render the
/// value honestly. The variants are mutually exclusive: a value is one
/// of `Captured`, `Redacted`, `Truncated`, `Unavailable`, or `Dropped`,
/// never two at once.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum CapturedValue {
    /// A real value was captured, redacted, and persisted.
    Captured {
        /// Coarse shape used to render the preview without revealing it.
        shape: ValueShape,
        /// Already-redacted preview safe to display.
        preview: SafePreview,
        /// Content hash over the pre-redaction value, used for
        /// integrity checks and stable references.
        digest: ContentHash,
    },
    /// The value was redacted by policy.
    Redacted {
        /// Stable identifier of the redaction rule that fired.
        rule_id: String,
        /// Optional shape hint so the UI can render a useful placeholder.
        shape_hint: Option<ValueShape>,
    },
    /// The value was captured but exceeded the per-value budget.
    Truncated {
        /// Redacted preview of the retained prefix.
        preview: SafePreview,
        /// Lower bound on the original size in bytes. The actual size
        /// may be larger because depth and element budgets shortened the
        /// representation before the byte budget was applied.
        original_size_lower_bound: u64,
        /// Effective limit that caused the truncation, in bytes.
        limit: u64,
    },
    /// The value could not be captured at all.
    Unavailable {
        /// Stable reason code for the absence.
        reason: UnavailableReason,
    },
    /// The value was dropped before durability.
    Dropped {
        /// Stable reason code for the drop.
        reason: DropReason,
    },
}

impl CapturedValue {
    /// Returns `true` if the variant contains redacted preview text.
    #[must_use]
    pub const fn has_preview(&self) -> bool {
        matches!(self, Self::Captured { .. } | Self::Truncated { .. })
    }

    /// Returns the redacted preview when one is present.
    #[must_use]
    pub fn preview(&self) -> Option<&SafePreview> {
        match self {
            Self::Captured { preview, .. } | Self::Truncated { preview, .. } => Some(preview),
            _ => None,
        }
    }
}

impl fmt::Debug for CapturedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Captured { shape, preview, .. } => {
                f.debug_struct("Captured").field("shape", shape).field("preview", preview).finish()
            }
            Self::Redacted { rule_id, shape_hint } => f
                .debug_struct("Redacted")
                .field("rule_id", rule_id)
                .field("shape_hint", shape_hint)
                .finish(),
            Self::Truncated { preview, original_size_lower_bound, limit } => f
                .debug_struct("Truncated")
                .field("preview", preview)
                .field("original_size_lower_bound", original_size_lower_bound)
                .field("limit", limit)
                .finish(),
            Self::Unavailable { reason } => {
                f.debug_struct("Unavailable").field("reason", reason).finish()
            }
            Self::Dropped { reason } => f.debug_struct("Dropped").field("reason", reason).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_only_available_when_present() {
        let captured = CapturedValue::Captured {
            shape: ValueShape::String,
            preview: SafePreview::from_redacted_unchecked("hello"),
            digest: ContentHash::of_bytes(b"hello"),
        };
        assert!(captured.has_preview());
        assert_eq!(captured.preview().expect("captured has preview").as_str(), "hello");

        let redacted = CapturedValue::Redacted { rule_id: "secret".to_string(), shape_hint: None };
        assert!(!redacted.has_preview());
        assert!(redacted.preview().is_none());
    }

    #[test]
    fn shape_label_is_stable() {
        assert_eq!(ValueShape::String.label(), "string");
        assert_eq!(
            ValueShape::List { length: 3 }.label(),
            "list",
            "shape labels must remain stable for UI tests"
        );
    }
}
