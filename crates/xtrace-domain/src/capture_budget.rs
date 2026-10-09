//! Capture budgets, event caps and shed priorities (ADR 0003 section 5, contracts section 2).
//!
//! One module mirrors the `CaptureCommand` defaults and the per-mode rules the daemon enforces at
//! ingest. Values are configuration with tested defaults; widening a bound later is additive,
//! narrowing one is not.

use serde::{Deserialize, Serialize};

/// Per-recording event cap in `standard` mode.
pub const STANDARD_EVENT_CAP: usize = 16_384;
/// Per-recording event cap in `focused` mode.
pub const FOCUSED_EVENT_CAP: usize = 131_072;
/// Hard sanity bound for any configured event cap (also the SQL CHECK in migration v7).
pub const EVENT_CAP_SANITY_BOUND: usize = 1_048_576;
/// Capture policy id for `standard` recordings.
pub const CAPTURE_POLICY_STANDARD_ID: &str = "xtrace.standard.v1";
/// Capture policy id for `focused` recordings.
pub const CAPTURE_POLICY_FOCUSED_ID: &str = "xtrace.focused.v1";

/// Capture depth of a recording.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    /// Function entry/exit/exception probes and async linkage only.
    #[default]
    Standard,
    /// Adds line cursors and local-variable values; opt-in per launch or arming.
    Focused,
}

impl CaptureMode {
    /// Per-recording event cap for the mode.
    #[must_use]
    pub const fn event_cap(self) -> usize {
        match self {
            Self::Standard => STANDARD_EVENT_CAP,
            Self::Focused => FOCUSED_EVENT_CAP,
        }
    }

    /// Capture policy id carried in `RecordingStarted.capture_policy_id`.
    #[must_use]
    pub const fn policy_id(self) -> &'static str {
        match self {
            Self::Standard => CAPTURE_POLICY_STANDARD_ID,
            Self::Focused => CAPTURE_POLICY_FOCUSED_ID,
        }
    }

    /// Resolves a claimed policy id. Empty and unknown ids mean `Standard`: a claim is not a grant.
    #[must_use]
    pub fn from_policy_id(id: &str) -> Self {
        if id == CAPTURE_POLICY_FOCUSED_ID { Self::Focused } else { Self::Standard }
    }

    /// Returns the lower of two modes (`Standard` < `Focused`), used to combine the armed mode with
    /// the adapter's claim.
    #[must_use]
    pub const fn min(self, other: Self) -> Self {
        match (self, other) {
            (Self::Focused, Self::Focused) => Self::Focused,
            _ => Self::Standard,
        }
    }

    /// Snake_case string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Focused => "focused",
        }
    }
}

/// Per-mode bounds on what one event, and one recording, may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureBudget {
    /// Longest `Captured.preview` or `Truncated.preview`, in bytes.
    pub max_preview_bytes: u32,
    /// Most bindings on one event.
    pub max_bindings_per_event: u16,
    /// Deepest container nesting rendered into a preview.
    pub container_depth: u8,
    /// Most container elements rendered into a preview.
    pub container_elements: u16,
    /// Most object fields rendered into a preview.
    pub object_fields: u16,
    /// Most preview plus name bytes on one event.
    pub max_event_value_bytes: u32,
    /// Most `LINE_CURSOR` events per recording. Zero in standard mode: line probes are focused-only
    /// (root decision 3; the ADR table's 1,024 is superseded and unused).
    pub max_line_events: u32,
    /// Most preview bytes per recording.
    pub max_value_bytes_per_recording: u64,
    /// Longest sanitized exception message, in bytes.
    pub max_exception_message_bytes: u16,
}

impl CaptureBudget {
    /// Budget for `standard` recordings.
    pub const STANDARD: Self = Self {
        max_preview_bytes: 256,
        max_bindings_per_event: 16,
        container_depth: 2,
        container_elements: 16,
        object_fields: 8,
        max_event_value_bytes: 4 * 1024,
        max_line_events: 0,
        max_value_bytes_per_recording: 256 * 1024,
        max_exception_message_bytes: 512,
    };

    /// Budget for `focused` recordings.
    pub const FOCUSED: Self = Self {
        max_preview_bytes: 512,
        max_bindings_per_event: 32,
        container_depth: 3,
        container_elements: 32,
        object_fields: 16,
        max_event_value_bytes: 16 * 1024,
        max_line_events: 8_192,
        max_value_bytes_per_recording: 4 * 1024 * 1024,
        max_exception_message_bytes: 512,
    };

    /// Budget for a mode.
    #[must_use]
    pub const fn for_mode(mode: CaptureMode) -> Self {
        match mode {
            CaptureMode::Standard => Self::STANDARD,
            CaptureMode::Focused => Self::FOCUSED,
        }
    }
}

/// Shed priorities: lower values are dropped first. These are the `RecordingEvent.priority` values
/// adapters emit and the buckets drop counts are reported under.
pub mod priority {
    /// Local variable values.
    pub const LOCAL: u32 = 10;
    /// Argument and return values.
    pub const ARGUMENT_RETURN: u32 = 15;
    /// Line cursors.
    pub const LINE_CURSOR: u32 = 20;
    /// Frame enter/exit/throw.
    pub const FRAME: u32 = 30;
    /// Database, outbound HTTP and other interactions.
    pub const INTERACTION: u32 = 40;
    /// Exceptions and the request outcome.
    pub const EXCEPTION_OUTCOME: u32 = 50;
    /// Request, lifecycle and structural events.
    pub const STRUCTURAL: u32 = 60;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_and_policy_ids_match_the_contract() {
        assert_eq!(CaptureMode::Standard.event_cap(), 16_384);
        assert_eq!(CaptureMode::Focused.event_cap(), 131_072);
        assert!(FOCUSED_EVENT_CAP <= EVENT_CAP_SANITY_BOUND);
        assert_eq!(CaptureMode::Standard.policy_id(), "xtrace.standard.v1");
        assert_eq!(CaptureMode::Focused.policy_id(), "xtrace.focused.v1");
    }

    #[test]
    fn unknown_and_empty_policy_ids_use_standard() {
        assert_eq!(CaptureMode::from_policy_id(""), CaptureMode::Standard);
        assert_eq!(CaptureMode::from_policy_id("xtrace.focused.v2"), CaptureMode::Standard);
        assert_eq!(CaptureMode::from_policy_id("xtrace.focused.v1"), CaptureMode::Focused);
    }

    #[test]
    fn effective_mode_is_the_lower_of_armed_and_claimed() {
        use CaptureMode::{Focused, Standard};
        assert_eq!(Focused.min(Focused), Focused);
        assert_eq!(Focused.min(Standard), Standard);
        assert_eq!(Standard.min(Focused), Standard);
    }

    #[test]
    fn standard_budget_has_no_line_events_and_is_narrower_than_focused() {
        let (s, f) = (CaptureBudget::STANDARD, CaptureBudget::FOCUSED);
        assert_eq!(s.max_line_events, 0);
        assert_eq!(f.max_line_events, 8_192);
        assert!(s.max_preview_bytes < f.max_preview_bytes);
        assert!(s.max_bindings_per_event < f.max_bindings_per_event);
        assert!(s.max_event_value_bytes < f.max_event_value_bytes);
        assert!(s.max_value_bytes_per_recording < f.max_value_bytes_per_recording);
        assert_eq!(CaptureBudget::for_mode(CaptureMode::Focused), f);
    }

    #[test]
    fn shed_priorities_are_ordered() {
        let order = [
            priority::LOCAL,
            priority::ARGUMENT_RETURN,
            priority::LINE_CURSOR,
            priority::FRAME,
            priority::INTERACTION,
            priority::EXCEPTION_OUTCOME,
            priority::STRUCTURAL,
        ];
        assert!(order.windows(2).all(|w| w[0] < w[1]));
    }
}
