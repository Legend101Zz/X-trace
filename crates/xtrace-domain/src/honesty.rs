//! Honesty marker vocabulary (ADR 0003 section 7 rules R1 to R8, contracts section 9).
//!
//! These snake_case strings are the only ones clients may key behaviour on. The summary counts are
//! computed server side; this module owns the vocabulary and the frame-flag bits only.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Stable honesty marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HonestyMarker {
    /// A value was redacted by policy.
    Redacted,
    /// A value was captured but cut at its budget.
    Truncated,
    /// A value or event was dropped before durability.
    Dropped,
    /// Events were not recorded; the gap names why.
    Gap,
    /// The recording is not complete.
    Incomplete,
    /// A value or fact could not be observed.
    Unavailable,
    /// The source file hash differs from the recording.
    Mismatch,
    /// The source file is absent.
    SourceMissing,
    /// A static or hypothesis claim, not observed.
    Inferred,
    /// The recording is not linked to an operation.
    Unmatched,
    /// The handler behind a route could not be resolved.
    HandlerUnresolved,
    /// Correlation between events was lost.
    CorrelationGap,
    /// Events past the per-recording cap were dropped.
    CapacityDroppedEvents,
    /// A stored object is missing.
    ObjectUnavailable,
    /// A stored object failed its checksum.
    ObjectCorrupt,
    /// A frame whose parent was not observed.
    OrphanParent,
    /// A row indexed before frame indexing existed.
    LegacyUnindexed,
}

impl HonestyMarker {
    /// Every marker, in declaration order.
    pub const ALL: [Self; 17] = [
        Self::Redacted,
        Self::Truncated,
        Self::Dropped,
        Self::Gap,
        Self::Incomplete,
        Self::Unavailable,
        Self::Mismatch,
        Self::SourceMissing,
        Self::Inferred,
        Self::Unmatched,
        Self::HandlerUnresolved,
        Self::CorrelationGap,
        Self::CapacityDroppedEvents,
        Self::ObjectUnavailable,
        Self::ObjectCorrupt,
        Self::OrphanParent,
        Self::LegacyUnindexed,
    ];

    /// The snake_case marker string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Redacted => "redacted",
            Self::Truncated => "truncated",
            Self::Dropped => "dropped",
            Self::Gap => "gap",
            Self::Incomplete => "incomplete",
            Self::Unavailable => "unavailable",
            Self::Mismatch => "mismatch",
            Self::SourceMissing => "source_missing",
            Self::Inferred => "inferred",
            Self::Unmatched => "unmatched",
            Self::HandlerUnresolved => "handler_unresolved",
            Self::CorrelationGap => "correlation_gap",
            Self::CapacityDroppedEvents => "capacity_dropped_events",
            Self::ObjectUnavailable => "object_unavailable",
            Self::ObjectCorrupt => "object_corrupt",
            Self::OrphanParent => "orphan_parent",
            Self::LegacyUnindexed => "legacy_unindexed",
        }
    }
}

impl fmt::Display for HonestyMarker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable bit flags stored per frame in `recording_frame_index.honesty_flags`. A frame is counted
/// once per flag regardless of how many bindings carry it.
pub mod honesty_flags {
    /// The frame has a gap event attached.
    pub const HAS_GAP: u32 = 1 << 0;
    /// A binding on the frame is redacted.
    pub const HAS_REDACTED: u32 = 1 << 1;
    /// A binding on the frame is truncated.
    pub const HAS_TRUNCATED: u32 = 1 << 2;
    /// A binding on the frame is unavailable.
    pub const HAS_UNAVAILABLE: u32 = 1 << 3;
    /// A binding on the frame is dropped.
    pub const HAS_DROPPED: u32 = 1 << 4;
    /// The frame carries at least one value binding.
    pub const HAS_VALUES: u32 = 1 << 5;
    /// The frame's parent was not observed.
    pub const ORPHAN_PARENT: u32 = 1 << 6;
    /// The frame exceeded the indexed depth bound.
    pub const DEPTH_OVERFLOW: u32 = 1 << 7;
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn marker_strings_are_unique_snake_case_and_match_serde() {
        let mut seen = BTreeSet::new();
        for marker in HonestyMarker::ALL {
            let text = marker.as_str();
            assert!(text.chars().all(|c| c.is_ascii_lowercase() || c == '_'), "{text}");
            assert!(seen.insert(text), "duplicate marker string {text}");
            let json = serde_json::to_string(&marker).expect("serialize");
            assert_eq!(json, format!("\"{text}\""));
        }
        assert_eq!(seen.len(), 17);
    }

    #[test]
    fn flag_bits_are_distinct_powers_of_two() {
        let flags = [
            honesty_flags::HAS_GAP,
            honesty_flags::HAS_REDACTED,
            honesty_flags::HAS_TRUNCATED,
            honesty_flags::HAS_UNAVAILABLE,
            honesty_flags::HAS_DROPPED,
            honesty_flags::HAS_VALUES,
            honesty_flags::ORPHAN_PARENT,
            honesty_flags::DEPTH_OVERFLOW,
        ];
        let combined = flags.iter().fold(0, |acc, f| acc | f);
        assert!(flags.iter().all(|f| f.is_power_of_two()));
        assert_eq!(combined, 0xFF);
    }
}
