//! Framework-neutral read use cases for persisted recordings.
//!
//! The application owns request bounds, stable projections, and the read port.
//! Infrastructure supplies metadata and already-verified persisted event
//! fields; no storage or protocol types cross this boundary.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    AppError, CapturedValue, CorrelationId, ErrorCategory, ErrorCode, FrameId, ProjectId,
    RecordingId, RetryAdvice, SourceBinding,
};

use crate::PortError;

/// Maximum number of recordings returned by one list request.
pub const MAX_RECORDING_LIST_LIMIT: u32 = 200;
/// Default number of recordings returned by one list request.
pub const DEFAULT_RECORDING_LIST_LIMIT: u32 = 50;
/// Maximum number of events returned by one show request.
pub const MAX_RECORDING_EVENT_LIMIT: u32 = 1_000;
/// Default number of events returned by one show request.
pub const DEFAULT_RECORDING_EVENT_LIMIT: u32 = 200;
/// Maximum serialized event projection bytes in one detail response.
pub const MAX_RECORDING_EVENT_PROJECTION_BYTES: usize = 256 * 1024;
/// Maximum verified compressed plus logical XTF bytes inspected in one show request.
///
/// The store may process one codec-bounded segment when that segment alone
/// crosses this threshold, ensuring a cursor can still make progress.
pub const MAX_RECORDING_VERIFIED_INPUT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum UTF-8 byte length for a projected display field.
pub const MAX_RECORDING_DISPLAY_FIELD_BYTES: usize = 256;
/// Maximum UTF-8 byte length for an exact projected relationship identifier.
pub const MAX_RECORDING_RELATIONSHIP_ID_BYTES: usize = 128;
/// Version of the stable JSON recording-read projection contract.
pub const RECORDING_READ_SCHEMA_VERSION: u32 = 3;

fn decimal_u64(value: &str) -> bool {
    value.parse::<u64>().is_ok_and(|parsed| parsed.to_string() == value)
}

/// Bounded request to list recordings in stable opening-time/ID order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListRecordings {
    /// Project whose recordings are read.
    pub project_id: ProjectId,
    /// Maximum page size, bounded by MAX_RECORDING_LIST_LIMIT.
    pub limit: u32,
    /// Exclusive recording-ID cursor from a prior page.
    pub after: Option<RecordingId>,
}

/// Bounded request to read one ordered event window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShowRecording {
    /// Project whose recording is read.
    pub project_id: ProjectId,
    /// Recording to read.
    pub recording_id: RecordingId,
    /// Maximum number of events, bounded by MAX_RECORDING_EVENT_LIMIT.
    pub limit: u32,
    /// Versioned opaque continuation returned by an earlier show response.
    pub cursor: Option<String>,
}

/// Versioned persisted lifecycle status; a nonterminal state is not completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingStatus {
    /// Recording anchor exists and capture may still be active.
    Recording,
    /// A terminal flush may be in progress; completion is not established.
    Finalizing,
    /// Persisted status explicitly records completion.
    Complete,
    /// Persisted status explicitly records incomplete capture.
    Partial,
    /// Persisted status explicitly records invalid capture.
    Invalid,
}

/// Whether terminal completion is proven by persisted finish evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingCompletionEvidence {
    /// Durable finish sequence and emitted-event-ID digest were verified.
    Complete,
    /// Durable finish proof is absent or explicitly records drops, gaps, or a partial stream.
    Partial,
    /// Durable finish evidence contradicted persisted event identity.
    Invalid,
    /// No verified terminal evidence exists, including historical rows.
    Unavailable,
}

/// Result of resolving one replay-navigation edge.
///
/// Internally tagged: `target` carries `frameId`, `boundary` carries nothing and
/// `unavailable` carries a stable `reason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum NavigationResult {
    /// The adjacent metadata index entry matched its immutable verified XTF event.
    Target {
        /// Frame the action lands on.
        frame_id: FrameId,
    },
    /// The verified sequence or recording boundary has no adjacent frame.
    Boundary,
    /// The relationship cannot be established from available event evidence.
    Unavailable {
        /// Why the relationship cannot be established.
        reason: NavigationUnavailable,
    },
}

impl NavigationResult {
    /// Unavailable with the supplied reason.
    #[must_use]
    pub const fn unavailable(reason: NavigationUnavailable) -> Self {
        Self::Unavailable { reason }
    }
}

/// Stable reasons a navigation edge is unavailable (snake_case on the wire).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NavigationUnavailable {
    /// The persisted frontier is not verified; more events may exist.
    PartialFrontier,
    /// The row predates the frame index that records depth and parents.
    LegacyUnindexed,
    /// The frame is deeper than the indexed depth bound.
    DepthOverflow,
    /// The parent was never observed.
    OrphanParent,
    /// The event is not a navigable frame.
    NotNavigable,
}

/// Bounded step-navigation facts for one indexed frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameNavigation {
    /// Previous frame in recording sequence order.
    pub previous: NavigationResult,
    /// Next frame in recording sequence order.
    pub next: NavigationResult,
    /// Verified child call frame, when a complete event graph proves one.
    pub into: NavigationResult,
    /// Verified next sibling frame, when a complete event graph proves one.
    pub over: NavigationResult,
    /// Verified parent call frame, when a complete event graph proves one.
    pub out: NavigationResult,
}

impl FrameNavigation {
    /// Navigation for legacy or unindexed events.
    pub const UNAVAILABLE: Self = Self {
        previous: NavigationResult::unavailable(NavigationUnavailable::LegacyUnindexed),
        next: NavigationResult::unavailable(NavigationUnavailable::LegacyUnindexed),
        into: NavigationResult::unavailable(NavigationUnavailable::LegacyUnindexed),
        over: NavigationResult::unavailable(NavigationUnavailable::LegacyUnindexed),
        out: NavigationResult::unavailable(NavigationUnavailable::LegacyUnindexed),
    };
}

/// Infrastructure read position decoded from a scoped show cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShowWindowRequest {
    /// Project whose recording is read.
    pub project_id: ProjectId,
    /// Recording to read.
    pub recording_id: RecordingId,
    /// Maximum returned events.
    pub limit: u32,
    /// Exclusive internal sequence offset decoded from a scoped cursor.
    pub after_sequence: Option<u64>,
}

/// Bounded interaction metadata from persisted XTF, excluding raw paths.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedInteraction {
    /// Persisted interaction kind, if recognized by this protocol version.
    pub kind: Option<String>,
    /// Persisted driver label.
    pub driver: Option<String>,
    /// Persisted database schema label.
    pub schema: Option<String>,
    /// Persisted table label.
    pub table: Option<String>,
    /// Persisted host label.
    pub host: Option<String>,
    /// Persisted method label.
    pub method: Option<String>,
}

/// Persisted event facts safe for a framework-neutral execution projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedEvent {
    /// Strictly ordered recording sequence.
    pub sequence: String,
    /// Stable UUIDv7 identity assigned on first durable frame-index insertion.
    pub frame_id: Option<FrameId>,
    /// Step navigation derived from the bounded persisted frame index.
    pub navigation: FrameNavigation,
    /// Adapter monotonic nanoseconds persisted with this event.
    pub monotonic_ns: String,
    /// Stable event identity persisted by the adapter.
    pub event_id: Option<String>,
    /// Parent event identity, when persisted.
    pub parent_event_id: Option<String>,
    /// Persisted async parent event identity, when present.
    pub async_parent_event_id: Option<String>,
    /// Persisted event kind label.
    pub kind: String,
    /// Persisted symbol or logical name.
    pub symbol: Option<String>,
    /// Persisted interaction projection, if present.
    pub interaction: Option<PersistedInteraction>,
    /// Compile-attested source location, if the loaded class was verified.
    pub source: Option<PersistedSource>,
    /// Runtime source-binding result persisted with the event.
    pub source_binding: SourceBinding,
    /// Explicit record of unprojected oversized fields without their contents.
    pub field_truncations: Vec<FieldTruncation>,
    /// Call depth from the frame index; `None` for legacy or unindexed rows.
    pub depth: Option<u32>,
    /// Parent frame, only when the parent was observed.
    pub parent_frame_id: Option<FrameId>,
    /// Async parent frame, only when the async parent was observed.
    pub async_parent_frame_id: Option<FrameId>,
    /// Observed line; `Some` only for `line_cursor` events, never a method extent.
    pub line: Option<u32>,
    /// Observed bindings; an empty list means none were observed.
    pub bindings: Vec<PersistedBinding>,
    /// Declared gap; `Some` only for `gap` events.
    pub gap: Option<PersistedGap>,
}

/// One observed binding (argument, local, field or return value) at an event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedBinding {
    /// Binding name as emitted (display-bounded).
    pub name: String,
    /// Binding role label (snake_case domain vocabulary).
    pub role: String,
    /// Where the name came from (snake_case domain vocabulary).
    pub name_origin: String,
    /// Observed value state.
    pub value: PersistedValue,
}

/// Value state of one binding; no state is ever a stand-in for another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum PersistedValue {
    /// Value preview captured and hashed.
    Captured {
        /// Sanitized value shape label.
        shape: String,
        /// Bounded sanitized preview.
        preview: String,
        /// `b3:<hex>` of the emitted preview bytes.
        content_hash: String,
    },
    /// Value withheld by a redaction rule.
    Redacted {
        /// Rule that withheld the value.
        rule_id: String,
        /// Optional shape hint safe to display.
        shape_hint: Option<String>,
    },
    /// Value cut at a budget.
    Truncated {
        /// Bounded sanitized preview.
        preview: String,
        /// Lower bound of the original size, decimal string.
        original_size_lower_bound: String,
        /// Limit that applied, decimal string.
        limit: String,
    },
    /// Value could not be observed.
    Unavailable {
        /// Snake_case domain reason.
        reason: String,
    },
    /// Value was dropped by a budget.
    Dropped {
        /// Snake_case domain reason.
        reason: String,
    },
}

/// Declared gap in the emitted event sequence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedGap {
    /// Snake_case gap reason.
    pub reason: String,
    /// Count of suppressed observations, decimal string.
    pub count: String,
    /// Nearest emitted sequence before the suppressed span, decimal string.
    pub first_sequence: String,
    /// Nearest emitted sequence after the suppressed span, decimal string.
    pub last_sequence: String,
}

/// Bounded source projection for one method event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedSource {
    /// Repository-relative source path; never an absolute local path.
    pub path: String,
    /// Lower bound of the compiled method's debug line extent (1-based).
    pub start_line: u32,
    /// Inclusive compiled method line extent, when debug metadata supplies it.
    pub end_line: Option<u32>,
    /// Current source comparison result.
    pub status: SourceStatus,
    /// Bounded source excerpt, present only when the file hash matches.
    pub excerpt: Option<String>,
    /// True when the source extent exceeded the excerpt window.
    pub truncated: bool,
}

/// Read-time status for matching current project source to the recorded hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    /// Current project source bytes match the recorded compile attestation.
    Matched,
    /// Current source exists but its bytes differ from the recorded identity.
    Mismatch,
    /// Source could not be read safely or usable metadata is absent.
    Unavailable,
    /// The recorded file is absent from the project source root.
    MissingFile,
}

/// Safe metadata describing a display or relationship field that was bounded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldTruncation {
    /// Stable projection field name.
    pub field: String,
    /// Original UTF-8 byte length, serialized as a decimal string.
    pub original_bytes: String,
    /// Whether a display placeholder or unavailable relationship was emitted.
    pub representation: FieldRepresentation,
}

/// Safe replacement used for an oversized persisted field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldRepresentation {
    /// Oversized display text was replaced by `[truncated]`.
    Truncated,
    /// Oversized identity or relationship was replaced by `[unavailable]`.
    Unavailable,
}

impl PersistedEvent {
    /// Bounds display and relationship strings without retaining their content.
    ///
    /// Canonical-sized identifiers remain exact. Oversized display text and
    /// relationships use fixed placeholders and record only field name and
    /// original byte length.
    pub fn bound_display_fields(&mut self) {
        bound_relationship_id(&mut self.event_id, "event_id", &mut self.field_truncations);
        bound_relationship_id(
            &mut self.parent_event_id,
            "parent_event_id",
            &mut self.field_truncations,
        );
        bound_relationship_id(
            &mut self.async_parent_event_id,
            "async_parent_event_id",
            &mut self.field_truncations,
        );
        bound_display(&mut self.symbol, "symbol", &mut self.field_truncations);
        if let Some(interaction) = &mut self.interaction {
            bound_display(
                &mut interaction.driver,
                "interaction.driver",
                &mut self.field_truncations,
            );
            bound_display(
                &mut interaction.schema,
                "interaction.schema",
                &mut self.field_truncations,
            );
            bound_display(&mut interaction.table, "interaction.table", &mut self.field_truncations);
            bound_display(&mut interaction.host, "interaction.host", &mut self.field_truncations);
            bound_display(
                &mut interaction.method,
                "interaction.method",
                &mut self.field_truncations,
            );
        }
        self.field_truncations.sort_by(|left, right| left.field.cmp(&right.field));
        self.field_truncations.dedup_by(|left, right| left.field == right.field);
    }

    /// Returns this event's compact JSON size plus one array separator byte.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the stable DTO cannot be rendered.
    pub fn serialized_size_with_separator(&self) -> Result<usize, serde_json::Error> {
        serde_json::to_vec(self).map(|bytes| bytes.len().saturating_add(1))
    }
}

fn bound_relationship_id(
    value: &mut Option<String>,
    field: &str,
    changed: &mut Vec<FieldTruncation>,
) {
    let Some(original) = value.as_ref() else {
        return;
    };
    if original.len() > MAX_RECORDING_RELATIONSHIP_ID_BYTES {
        let original_bytes = original.len().to_string();
        *value = Some("[unavailable]".to_owned());
        changed.push(FieldTruncation {
            field: field.to_owned(),
            original_bytes,
            representation: FieldRepresentation::Unavailable,
        });
    }
}

fn bound_display(value: &mut Option<String>, field: &str, changed: &mut Vec<FieldTruncation>) {
    let Some(original) = value.as_ref() else {
        return;
    };
    if original.len() <= MAX_RECORDING_DISPLAY_FIELD_BYTES {
        return;
    }
    let original_bytes = original.len().to_string();
    *value = Some("[truncated]".to_owned());
    changed.push(FieldTruncation {
        field: field.to_owned(),
        original_bytes,
        representation: FieldRepresentation::Truncated,
    });
}

/// Recording facts read from durable metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingMetadata {
    /// Stable recording identity.
    pub recording_id: RecordingId,
    /// Exact persisted lifecycle status.
    pub status: RecordingStatus,
    /// Completion state established from durable finish evidence.
    pub completion: RecordingCompletionEvidence,
    /// Persisted opening wall time.
    pub opened_at: String,
    /// Number of durable segment rows.
    pub segment_count: String,
    /// Number of durable events across segments.
    pub event_count: String,
    /// First persisted sequence, if a segment exists.
    pub first_sequence: Option<String>,
    /// Last persisted sequence, if a segment exists.
    pub last_sequence: Option<String>,
    /// Persisted incomplete status evidence; no completion is inferred otherwise.
    pub incomplete_evidence: Vec<String>,
    /// Event cap recorded in terminal evidence, when present.
    pub event_cap: Option<u32>,
    /// Outcome kind recorded in terminal evidence, when present.
    pub outcome_kind: Option<String>,
}

/// One verified segment window returned by the storage adapter.
#[derive(Clone, Debug, PartialEq)]
pub struct RecordingEventWindow {
    /// Stable recording identity.
    pub recording_id: RecordingId,
    /// Exact persisted lifecycle status.
    pub status: RecordingStatus,
    /// Completion state established from durable finish evidence.
    pub completion: RecordingCompletionEvidence,
    /// Producer-declared sanitized summary from terminal evidence; this is not independently
    /// correlated to a response event and must not be presented as outcome proof.
    pub adapter_summary: Option<CapturedValue>,
    /// Adapter-declared duration; absent for legacy or unavailable evidence.
    pub duration_ns: Option<String>,
    /// Adapter-reported dropped-event counts by numeric priority bucket.
    pub drop_counts_by_priority: BTreeMap<u32, String>,
    /// Number of durable segments in the recording.
    pub segment_count: String,
    /// Persisted events in strict sequence order.
    pub events: Vec<PersistedEvent>,
    /// Indicates that a bounded continuation can produce another window.
    pub has_more: bool,
    /// Exact incomplete status or observed sequence-gap marker evidence.
    pub incomplete_evidence: Vec<String>,
    /// Adapter-observed outcome; `None` when terminal evidence is absent.
    pub outcome: Option<PersistedOutcome>,
    /// Event capacity facts; `None` when terminal evidence is absent.
    pub capacity: Option<RecordingCapacity>,
    /// Stable limitation codes recorded for this recording.
    pub limitations: Vec<String>,
}

/// Adapter-observed outcome of the recorded operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedOutcome {
    /// `responded`, `exception` or `unobserved` (snake_case).
    pub kind: String,
    /// HTTP status when observed.
    pub http_status: Option<u16>,
    /// Propagated exception facts when the outcome is an exception.
    pub exception: Option<OutcomeException>,
    /// Event the exception was thrown from, when observed.
    pub thrown_from_event_id: Option<String>,
}

/// Sanitized exception facts attached to an outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeException {
    /// Exception type name, bounded.
    pub exception_type: String,
    /// Sanitized message, bounded, when present.
    pub message: Option<String>,
}

/// Event capacity facts from terminal evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordingCapacity {
    /// Cap in force for this recording.
    pub event_cap: u32,
    /// Events persisted.
    pub event_count: u32,
    /// Events dropped at the cap, decimal string.
    pub capacity_dropped_events: String,
    /// Dropped-event counts by priority, decimal strings.
    pub drops_by_priority: BTreeMap<u32, String>,
}

/// Which event projection a window carries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Projection {
    /// Every event field, including navigation, ids and bindings.
    #[default]
    Full,
    /// Outline fields only.
    Structure,
}

/// Server-computed honesty counts; clients render these and never recompute them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HonestySummary {
    /// Version of this summary shape.
    pub schema_version: u32,
    /// Whole-recording facts.
    pub recording: HonestyRecording,
    /// Facts about the returned window only.
    pub window: HonestyWindow,
}

/// Whole-recording honesty facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HonestyRecording {
    /// `complete`, `partial`, `invalid` or `unavailable`.
    pub completion: String,
    /// Incomplete-evidence strings.
    pub incomplete: Vec<String>,
    /// Events dropped at the cap, decimal string.
    pub capacity_dropped_events: String,
    /// Dropped counts by priority, decimal strings.
    pub drops_by_priority: BTreeMap<u32, String>,
    /// Frames carrying a gap flag; `None` when counts are unavailable.
    pub frames_with_gap: Option<u64>,
    /// Frames carrying a redacted value; `None` when counts are unavailable.
    pub frames_with_redacted: Option<u64>,
    /// Frames carrying a truncated value; `None` when counts are unavailable.
    pub frames_with_truncated: Option<u64>,
    /// Frames carrying an unavailable value; `None` when counts are unavailable.
    pub frames_with_unavailable: Option<u64>,
    /// Frames carrying a dropped value; `None` when counts are unavailable.
    pub frames_with_dropped: Option<u64>,
    /// Frames with an unobserved parent; `None` when counts are unavailable.
    pub frames_with_orphan_parent: Option<u64>,
    /// False when the frame counts cannot be computed (never zero-filled).
    pub counts_available: bool,
}

/// Honesty facts for the returned window.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HonestyWindow {
    /// Events in the window.
    pub events: u64,
    /// Bindings by value state.
    pub bindings_by_state: BTreeMap<String, u64>,
    /// Unavailable values by reason.
    pub unavailable_by_reason: BTreeMap<String, u64>,
    /// Dropped values by reason.
    pub dropped_by_reason: BTreeMap<String, u64>,
    /// Gap events in the window.
    pub gaps: Vec<WindowGap>,
    /// Events by source-binding state.
    pub source_bindings: BTreeMap<String, u64>,
    /// Projected sources by status.
    pub source_status: BTreeMap<String, u64>,
}

/// One gap event in the window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowGap {
    /// Gap event sequence, decimal string.
    pub sequence: String,
    /// Snake_case gap reason.
    pub reason: String,
    /// Suppressed observation count, decimal string.
    pub count: String,
    /// Bracketing sequence before the span, decimal string.
    pub first_sequence: String,
    /// Bracketing sequence after the span, decimal string.
    pub last_sequence: String,
}

impl HonestySummary {
    /// Builds the summary from the facts a window carries; whole-recording frame
    /// counts stay unavailable until the frame index supplies them.
    #[must_use]
    pub fn from_window(
        completion: RecordingCompletionEvidence,
        incomplete: &[String],
        capacity: Option<&RecordingCapacity>,
        drops_by_priority: &BTreeMap<u32, String>,
        events: &[PersistedEvent],
    ) -> Self {
        let mut window = HonestyWindow { events: events.len() as u64, ..HonestyWindow::default() };
        for event in events {
            for binding in &event.bindings {
                let (state, reason) = match &binding.value {
                    PersistedValue::Captured { .. } => ("captured", None),
                    PersistedValue::Redacted { .. } => ("redacted", None),
                    PersistedValue::Truncated { .. } => ("truncated", None),
                    PersistedValue::Unavailable { reason } => ("unavailable", Some(reason)),
                    PersistedValue::Dropped { reason } => ("dropped", Some(reason)),
                };
                *window.bindings_by_state.entry(state.to_owned()).or_default() += 1;
                if let Some(reason) = reason {
                    let map = if state == "unavailable" {
                        &mut window.unavailable_by_reason
                    } else {
                        &mut window.dropped_by_reason
                    };
                    *map.entry(reason.clone()).or_default() += 1;
                }
            }
            if let Some(gap) = &event.gap {
                window.gaps.push(WindowGap {
                    sequence: event.sequence.clone(),
                    reason: gap.reason.clone(),
                    count: gap.count.clone(),
                    first_sequence: gap.first_sequence.clone(),
                    last_sequence: gap.last_sequence.clone(),
                });
            }
            let binding = serde_json::to_value(event.source_binding)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unspecified".to_owned());
            *window.source_bindings.entry(binding).or_default() += 1;
            if let Some(source) = &event.source {
                let status = match source.status {
                    SourceStatus::Matched => "matched",
                    SourceStatus::Mismatch => "mismatch",
                    SourceStatus::Unavailable => "unavailable",
                    SourceStatus::MissingFile => "missing_file",
                };
                *window.source_status.entry(status.to_owned()).or_default() += 1;
            }
        }
        let completion_label = match completion {
            RecordingCompletionEvidence::Complete => "complete",
            RecordingCompletionEvidence::Partial => "partial",
            RecordingCompletionEvidence::Invalid => "invalid",
            RecordingCompletionEvidence::Unavailable => "unavailable",
        };
        Self {
            schema_version: 1,
            recording: HonestyRecording {
                completion: completion_label.to_owned(),
                incomplete: incomplete.to_vec(),
                capacity_dropped_events: capacity
                    .map_or_else(|| "0".to_owned(), |value| value.capacity_dropped_events.clone()),
                drops_by_priority: drops_by_priority.clone(),
                frames_with_gap: None,
                frames_with_redacted: None,
                frames_with_truncated: None,
                frames_with_unavailable: None,
                frames_with_dropped: None,
                frames_with_orphan_parent: None,
                counts_available: false,
            },
            window,
        }
    }
}

/// Stable JSON list projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingListPage {
    /// Version of this stable JSON projection contract.
    pub schema_version: u32,
    /// Selected project.
    pub project_id: ProjectId,
    /// Requested page bound.
    pub limit: u32,
    /// Exclusive cursor supplied by the caller.
    pub after: Option<RecordingId>,
    /// Rows ordered by descending opening time and recording ID.
    pub recordings: Vec<RecordingMetadata>,
    /// Cursor to pass to the next page, if more results exist.
    pub next_after: Option<RecordingId>,
    /// Capture semantics deliberately excluded from metadata or not written yet.
    pub unavailable: UnavailableEvidence,
}

/// Stable JSON detail projection for a Linear event window.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecordingDetail {
    /// Version of this stable JSON projection contract.
    pub schema_version: u32,
    /// Selected project.
    pub project_id: ProjectId,
    /// Recording identity.
    pub recording_id: RecordingId,
    /// Exact persisted lifecycle status.
    pub status: RecordingStatus,
    /// Completion state established from durable finish evidence.
    pub completion: RecordingCompletionEvidence,
    /// Producer-declared sanitized summary from terminal evidence; this is not independently
    /// correlated to a response event and must not be presented as outcome proof.
    pub adapter_summary: Option<CapturedValue>,
    /// Adapter-declared duration; absent for legacy or unavailable evidence.
    pub duration_ns: Option<String>,
    /// Adapter-reported dropped-event counts by numeric priority bucket.
    pub drop_counts_by_priority: BTreeMap<u32, String>,
    /// Requested event limit.
    pub limit: u32,
    /// Versioned, project- and recording-bound cursor supplied by the caller.
    pub cursor: Option<String>,
    /// Versioned, project- and recording-bound continuation, if more data exists.
    pub next_cursor: Option<String>,
    /// Number of persisted segments backing the recording.
    pub segment_count: String,
    /// Returned, ordered persisted events.
    pub events: Vec<PersistedEvent>,
    /// Evidence that this persisted recording is incomplete.
    pub incomplete_evidence: Vec<String>,
    /// Source, value, and completion details absent from this persistence slice.
    pub unavailable: UnavailableEvidence,
    /// Adapter-observed outcome; `None` when terminal evidence is absent.
    pub outcome: Option<PersistedOutcome>,
    /// Event capacity facts; `None` when terminal evidence is absent.
    pub capacity: Option<RecordingCapacity>,
    /// Stable limitation codes (for example `capture_policy_not_armed`).
    pub limitations: Vec<String>,
    /// Server-computed honesty summary.
    pub honesty: HonestySummary,
    /// Anchor frame of an `aroundFrame` window.
    pub anchor_frame_id: Option<FrameId>,
    /// First sequence in the returned window, decimal string.
    pub first_sequence: Option<String>,
    /// Last sequence in the returned window, decimal string.
    pub last_sequence: Option<String>,
    /// Backward-paging cursor, when an earlier window exists.
    pub prev_cursor: Option<String>,
    /// Projection the events carry.
    pub projection: Projection,
}

/// Explicit representation of details this projection cannot establish.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnavailableEvidence {
    /// Source locations are not projected by this query contract.
    pub source: String,
    /// Event-level captured values are excluded; finish response summary is projected separately.
    pub values: String,
    /// Whether durable terminal evidence exists; the typed `completion` field carries its result.
    pub completion: String,
}

impl Default for UnavailableEvidence {
    fn default() -> Self {
        Self {
            source: "unavailable".to_owned(),
            values: "unavailable".to_owned(),
            completion: "unavailable".to_owned(),
        }
    }
}

/// Infrastructure contract for bounded persisted-recording reads.
pub trait RecordingReadPort: Send + Sync {
    /// Lists one stable, bounded page and reports whether another page exists.
    fn list_recordings(
        &self,
        project_id: ProjectId,
        after: Option<RecordingId>,
        limit: u32,
    ) -> Result<(Vec<RecordingMetadata>, bool), PortError>;

    /// Reads and verifies one bounded event window for a project-owned recording.
    fn show_recording(
        &self,
        request: &ShowWindowRequest,
    ) -> Result<RecordingEventWindow, PortError>;
}

/// Shared framework-neutral facade for bounded persisted-recording reads.
///
/// CLI and local HTTP clients compose the same service with an implementation
/// of [`RecordingReadPort`]. This type owns application validation and
/// projection; it has no storage, path, or transport knowledge.
#[derive(Clone)]
pub struct RecordingQueryService<P> {
    port: P,
}

impl<P: RecordingReadPort> RecordingQueryService<P> {
    /// Creates a recording query facade over the supplied read port.
    pub const fn new(port: P) -> Self {
        Self { port }
    }

    /// Lists a bounded deterministic page of persisted recordings.
    ///
    /// # Errors
    ///
    /// Returns a typed application error for invalid bounds or a sanitized
    /// read-port failure.
    pub fn list(
        &self,
        request: ListRecordings,
        correlation_id: CorrelationId,
    ) -> Result<RecordingListPage, AppError> {
        list_recordings(&self.port, request, correlation_id)
    }

    /// Reads one bounded verified event window for the Linear projection.
    ///
    /// # Errors
    ///
    /// Returns a typed application error for invalid bounds/cursors or a
    /// sanitized read-port failure.
    pub fn show(
        &self,
        request: ShowRecording,
        correlation_id: CorrelationId,
    ) -> Result<RecordingDetail, AppError> {
        show_recording(&self.port, request, correlation_id)
    }
}

/// Lists persisted recordings after validating application-owned bounds.
///
/// # Errors
///
/// Returns a validation error for a zero or oversized limit and propagates a
/// sanitized storage-port error otherwise.
pub fn list_recordings<P: RecordingReadPort>(
    port: &P,
    request: ListRecordings,
    correlation_id: CorrelationId,
) -> Result<RecordingListPage, AppError> {
    if request.limit == 0 || request.limit > MAX_RECORDING_LIST_LIMIT {
        return Err(query_validation_error(correlation_id));
    }
    let (recordings, has_more) = port
        .list_recordings(request.project_id, request.after, request.limit)
        .map_err(|error| crate::application::port_error_to_app_error(error, correlation_id))?;
    let next_after =
        has_more.then(|| recordings.last().map(|recording| recording.recording_id)).flatten();
    let unavailable = UnavailableEvidence {
        completion: "per_recording".to_owned(),
        ..UnavailableEvidence::default()
    };
    Ok(RecordingListPage {
        schema_version: RECORDING_READ_SCHEMA_VERSION,
        project_id: request.project_id,
        limit: request.limit,
        after: request.after,
        recordings,
        next_after,
        unavailable,
    })
}

/// Loads a bounded persisted event window for the Linear read surface.
///
/// # Errors
///
/// Returns a validation error for a zero or oversized limit and propagates a
/// sanitized storage-port error otherwise.
pub fn show_recording<P: RecordingReadPort>(
    port: &P,
    request: ShowRecording,
    correlation_id: CorrelationId,
) -> Result<RecordingDetail, AppError> {
    if request.limit == 0 || request.limit > MAX_RECORDING_EVENT_LIMIT {
        return Err(query_validation_error(correlation_id));
    }
    let after_sequence = request
        .cursor
        .as_deref()
        .map(decode_cursor)
        .transpose()
        .map_err(|()| cursor_validation_error(correlation_id))?;
    if after_sequence.is_some_and(|cursor| {
        cursor.project_id != request.project_id || cursor.recording_id != request.recording_id
    }) {
        return Err(cursor_validation_error(correlation_id));
    }
    let position = ShowWindowRequest {
        project_id: request.project_id,
        recording_id: request.recording_id,
        limit: request.limit,
        after_sequence: after_sequence.map(|cursor| cursor.sequence),
    };
    let window = port
        .show_recording(&position)
        .map_err(|error| crate::application::port_error_to_app_error(error, correlation_id))?;
    let adapter_summary = window.adapter_summary;
    if window.duration_ns.as_ref().is_some_and(|value| !decimal_u64(value))
        || window.drop_counts_by_priority.len() > 256
        || window.drop_counts_by_priority.values().any(|value| !decimal_u64(value))
    {
        return Err(query_resource_error(correlation_id));
    }
    let duration_ns = window.duration_ns;
    let drop_counts_by_priority = window.drop_counts_by_priority;
    let summary_bytes = adapter_summary
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|_| query_resource_error(correlation_id))?
        .map_or(0, |bytes| bytes.len().saturating_add(1));
    let terminal_metadata_bytes =
        serde_json::to_vec(&(duration_ns.as_ref(), &drop_counts_by_priority))
            .map_err(|_| query_resource_error(correlation_id))?
            .len()
            .saturating_add(1);
    let auxiliary_bytes = summary_bytes.checked_add(terminal_metadata_bytes);
    let Some(auxiliary_bytes) = auxiliary_bytes else {
        return Err(query_resource_error(correlation_id));
    };
    if auxiliary_bytes > MAX_RECORDING_EVENT_PROJECTION_BYTES {
        return Err(query_resource_error(correlation_id));
    }
    let mut events = window.events;
    for event in &mut events {
        event.bound_display_fields();
    }
    let initial_projection_bytes = 2_usize.saturating_add(auxiliary_bytes);
    let projection_bytes = events.iter().try_fold(initial_projection_bytes, |total, event| {
        total.checked_add(event.serialized_size_with_separator().ok()?)
    });
    if projection_bytes.is_none_or(|bytes| bytes > MAX_RECORDING_EVENT_PROJECTION_BYTES) {
        return Err(query_resource_error(correlation_id));
    }
    let next_cursor = if window.has_more {
        let sequence = events
            .last()
            .and_then(|event| event.sequence.parse::<u64>().ok())
            .ok_or_else(|| query_resource_error(correlation_id))?;
        Some(encode_cursor(CursorPayload {
            project_id: request.project_id,
            recording_id: request.recording_id,
            sequence,
        }))
    } else {
        None
    };
    let honesty = HonestySummary::from_window(
        window.completion,
        &window.incomplete_evidence,
        window.capacity.as_ref(),
        &drop_counts_by_priority,
        &events,
    );
    let first_sequence = events.first().map(|event| event.sequence.clone());
    let last_sequence = events.last().map(|event| event.sequence.clone());
    Ok(RecordingDetail {
        schema_version: RECORDING_READ_SCHEMA_VERSION,
        project_id: request.project_id,
        recording_id: window.recording_id,
        status: window.status,
        completion: window.completion,
        adapter_summary,
        duration_ns,
        drop_counts_by_priority,
        limit: request.limit,
        cursor: request.cursor,
        next_cursor,
        segment_count: window.segment_count,
        events,
        incomplete_evidence: window.incomplete_evidence,
        unavailable: UnavailableEvidence {
            completion: if window.completion == RecordingCompletionEvidence::Unavailable {
                "unavailable".to_owned()
            } else {
                "available".to_owned()
            },
            ..UnavailableEvidence::default()
        },
        outcome: window.outcome,
        capacity: window.capacity,
        limitations: window.limitations,
        honesty,
        anchor_frame_id: None,
        first_sequence,
        last_sequence,
        prev_cursor: None,
        projection: Projection::Full,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CursorPayload {
    project_id: ProjectId,
    recording_id: RecordingId,
    sequence: u64,
}

fn encode_cursor(cursor: CursorPayload) -> String {
    let mut payload = Vec::with_capacity(40);
    payload.extend_from_slice(cursor.project_id.as_uuid().as_bytes());
    payload.extend_from_slice(cursor.recording_id.as_uuid().as_bytes());
    payload.extend_from_slice(&cursor.sequence.to_be_bytes());
    format!("v1.{}", URL_SAFE_NO_PAD.encode(payload))
}

fn decode_cursor(token: &str) -> Result<CursorPayload, ()> {
    let encoded = token.strip_prefix("v1.").ok_or(())?;
    if encoded.len() > 128 {
        return Err(());
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| ())?;
    if bytes.len() != 40 {
        return Err(());
    }
    let project_bytes: [u8; 16] = bytes[..16].try_into().map_err(|_| ())?;
    let recording_bytes: [u8; 16] = bytes[16..32].try_into().map_err(|_| ())?;
    let sequence_bytes: [u8; 8] = bytes[32..].try_into().map_err(|_| ())?;
    Ok(CursorPayload {
        project_id: ProjectId::from_uuid(uuid::Uuid::from_bytes(project_bytes)),
        recording_id: RecordingId::from_uuid(uuid::Uuid::from_bytes(recording_bytes)),
        sequence: u64::from_be_bytes(sequence_bytes),
    })
}

fn query_validation_error(correlation_id: CorrelationId) -> AppError {
    AppError::new(
        ErrorCode::new("XTR-VALIDATION-RECORDING-QUERY"),
        ErrorCategory::Validation,
        "recording query limit is outside supported bounds",
        RetryAdvice::None,
        correlation_id,
    )
}

fn cursor_validation_error(correlation_id: CorrelationId) -> AppError {
    AppError::new(
        ErrorCode::new("XTR-VALIDATION-RECORDING-CURSOR"),
        ErrorCategory::Validation,
        "recording cursor is malformed or belongs to a different project or recording",
        RetryAdvice::None,
        correlation_id,
    )
}

fn query_resource_error(correlation_id: CorrelationId) -> AppError {
    AppError::new(
        ErrorCode::new("XTR-RESOURCE-RECORDING-PROJECTION"),
        ErrorCategory::Resource,
        "recording event projection exceeds its bounded response budget",
        RetryAdvice::None,
        correlation_id,
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "fixed query fixtures")]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct ReadFixture {
        list: Vec<RecordingMetadata>,
        window: RecordingEventWindow,
    }

    impl RecordingReadPort for ReadFixture {
        fn list_recordings(
            &self,
            _project_id: ProjectId,
            _after: Option<RecordingId>,
            _limit: u32,
        ) -> Result<(Vec<RecordingMetadata>, bool), PortError> {
            Ok((self.list.clone(), true))
        }

        fn show_recording(
            &self,
            _request: &ShowWindowRequest,
        ) -> Result<RecordingEventWindow, PortError> {
            Ok(self.window.clone())
        }
    }

    fn fixture() -> (ProjectId, RecordingId, ReadFixture) {
        let project_id = ProjectId::new();
        let recording_id = RecordingId::new();
        let window = RecordingEventWindow {
            recording_id,
            status: RecordingStatus::Recording,
            completion: RecordingCompletionEvidence::Unavailable,
            adapter_summary: None,
            duration_ns: None,
            drop_counts_by_priority: BTreeMap::new(),
            segment_count: "1".to_owned(),
            events: vec![PersistedEvent {
                sequence: u64::MAX.to_string(),
                frame_id: Some(FrameId::new()),
                navigation: FrameNavigation::UNAVAILABLE,
                monotonic_ns: u64::MAX.to_string(),
                event_id: Some("persisted-event".to_owned()),
                parent_event_id: None,
                async_parent_event_id: Some("async-parent".to_owned()),
                kind: "unknown:2147483647".to_owned(),
                symbol: None,
                interaction: None,
                source: None,
                source_binding: SourceBinding::Unspecified,
                field_truncations: Vec::new(),
                depth: None,
                parent_frame_id: None,
                async_parent_frame_id: None,
                line: None,
                bindings: Vec::new(),
                gap: None,
            }],
            has_more: true,
            incomplete_evidence: Vec::new(),
            outcome: None,
            capacity: None,
            limitations: Vec::new(),
        };
        let list = vec![RecordingMetadata {
            recording_id,
            status: RecordingStatus::Partial,
            completion: RecordingCompletionEvidence::Unavailable,
            opened_at: "2026-09-30T00:00:00Z".to_owned(),
            segment_count: "1".to_owned(),
            event_count: u64::MAX.to_string(),
            first_sequence: Some("2".to_owned()),
            last_sequence: Some(u64::MAX.to_string()),
            incomplete_evidence: vec!["persisted_status:partial".to_owned()],
            event_cap: None,
            outcome_kind: None,
        }];
        (project_id, recording_id, ReadFixture { list, window })
    }

    #[test]
    fn shared_recording_query_service_uses_the_same_bounded_contract() {
        let (project_id, recording_id, fixture) = fixture();
        let service = RecordingQueryService::new(fixture);
        let list = service
            .list(ListRecordings { project_id, limit: 1, after: None }, CorrelationId::new())
            .expect("list through shared service");
        assert_eq!(list.schema_version, RECORDING_READ_SCHEMA_VERSION);
        assert_eq!(list.project_id, project_id);

        let detail = service
            .show(
                ShowRecording { project_id, recording_id, limit: 1, cursor: None },
                CorrelationId::new(),
            )
            .expect("show through shared service");
        assert_eq!(detail.recording_id, recording_id);
        assert_eq!(detail.events.len(), 1);
    }

    #[test]
    fn list_keeps_store_order_and_returns_a_deterministic_cursor() {
        let (project_id, recording_id, fixture) = fixture();
        let result = list_recordings(
            &fixture,
            ListRecordings { project_id, limit: 1, after: None },
            CorrelationId::new(),
        )
        .expect("list fixture");
        assert_eq!(result.recordings[0].recording_id, recording_id);
        assert_eq!(result.next_after, Some(recording_id));
        assert_eq!(result.schema_version, RECORDING_READ_SCHEMA_VERSION);
        assert_eq!(result.recordings[0].incomplete_evidence, ["persisted_status:partial"]);
        assert_eq!(result.unavailable.values, "unavailable");
    }

    #[test]
    fn show_preserves_full_unsigned_values_as_decimal_strings() {
        let (project_id, recording_id, fixture) = fixture();
        let result = show_recording(
            &fixture,
            ShowRecording {
                project_id,
                recording_id,
                limit: 1,
                cursor: Some(encode_cursor(CursorPayload {
                    project_id,
                    recording_id,
                    sequence: 4,
                })),
            },
            CorrelationId::new(),
        )
        .expect("show fixture");
        let json = serde_json::to_string(&result).expect("serialize fixture");
        assert!(json.contains(&format!("\"sequence\":\"{}\"", u64::MAX)));
        assert!(json.contains(&format!("\"monotonic_ns\":\"{}\"", u64::MAX)));
        assert!(json.contains("\"completion\":\"unavailable\""));
        assert!(!json.contains("\"sequence\":18446744073709551615"));
        assert!(!json.contains("next_after_sequence"));
        assert!(json.contains("next_cursor"));
        assert_eq!(result.schema_version, RECORDING_READ_SCHEMA_VERSION);
        assert_eq!(result.events[0].async_parent_event_id.as_deref(), Some("async-parent"));
        let next = decode_cursor(result.next_cursor.as_deref().expect("next cursor"))
            .expect("decode scoped cursor");
        assert_eq!(next.sequence, u64::MAX);
        assert_eq!(next.project_id, project_id);
        assert_eq!(next.recording_id, recording_id);
    }

    #[test]
    fn list_and_show_reject_zero_and_oversized_limits() {
        let (project_id, recording_id, fixture) = fixture();
        for limit in [0, MAX_RECORDING_LIST_LIMIT + 1] {
            let error = list_recordings(
                &fixture,
                ListRecordings { project_id, limit, after: None },
                CorrelationId::new(),
            )
            .expect_err("invalid list bound");
            assert_eq!(error.category, ErrorCategory::Validation);
        }
        for limit in [0, MAX_RECORDING_EVENT_LIMIT + 1] {
            let error = show_recording(
                &fixture,
                ShowRecording { project_id, recording_id, limit, cursor: None },
                CorrelationId::new(),
            )
            .expect_err("invalid event bound");
            assert_eq!(error.category, ErrorCategory::Validation);
        }
    }

    #[test]
    fn show_cursor_is_versioned_and_bound_to_project_and_recording() {
        let (project_id, recording_id, fixture) = fixture();
        let other_project = ProjectId::new();
        let other_recording = RecordingId::new();
        let tokens = [
            "bad-token".to_owned(),
            encode_cursor(CursorPayload { project_id: other_project, recording_id, sequence: 2 }),
            encode_cursor(CursorPayload { project_id, recording_id: other_recording, sequence: 2 }),
        ];
        for cursor in tokens {
            let error = show_recording(
                &fixture,
                ShowRecording { project_id, recording_id, limit: 10, cursor: Some(cursor) },
                CorrelationId::new(),
            )
            .expect_err("malformed or cross-bound cursor rejected");
            assert_eq!(error.code.as_str(), "XTR-VALIDATION-RECORDING-CURSOR");
        }
    }

    #[test]
    fn oversized_display_fields_are_redacted_with_explicit_metadata() {
        let (project_id, recording_id, mut fixture) = fixture();
        fixture.window.events[0].symbol = Some("SYMBOL_CANARY".repeat(30_000));
        fixture.window.events[0].event_id = Some("relationship-canary".repeat(20));
        let result = show_recording(
            &fixture,
            ShowRecording { project_id, recording_id, limit: 10, cursor: None },
            CorrelationId::new(),
        )
        .expect("oversized event is represented within the response budget");
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].symbol.as_deref(), Some("[truncated]"));
        assert_eq!(result.events[0].event_id.as_deref(), Some("[unavailable]"));
        assert!(result.next_cursor.is_some());
        assert!(result.events[0].field_truncations.iter().any(|field| {
            field.field == "symbol"
                && field.representation == FieldRepresentation::Truncated
                && field.original_bytes.parse::<usize>().unwrap()
                    > MAX_RECORDING_EVENT_PROJECTION_BYTES
        }));
        assert!(result.events[0].field_truncations.iter().any(|field| {
            field.field == "event_id" && field.representation == FieldRepresentation::Unavailable
        }));
        let json = serde_json::to_string(&result).expect("serialize bounded event");
        assert!(!json.contains("SYMBOL_CANARY"));
        assert!(!json.contains("relationship-canary"));
    }
}
