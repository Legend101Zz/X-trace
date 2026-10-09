//! Per-event validation rules (CONTRACTS section 3).
//!
//! Pure functions over wire payloads. The [`crate::IngestValidator`] runs [`validate_event`] in the
//! batch preflight, so a bad event rejects the whole batch before any state changes. Every rule
//! error is recoverable (`is_session_fatal() == false`): the adapter must resend a corrected event
//! at the same `recording_seq`, which is why emitters must never produce one.

use uuid::Uuid;
use xtrace_domain::{
    BindingRole, CaptureBudget, CaptureMode, SourceBinding, is_safe_repo_relative_path,
};
use xtrace_protocol::generated::agent::{
    self as wire, RecordingEvent, RecordingEventKind, RecordingFinished, RecordingStarted,
    RuntimeFacts, captured_value::Value,
};
use xtrace_protocol::translate::{
    binding_role_from_wire, drop_reason_from_wire, gap_from_wire, name_origin_from_wire,
    outcome_from_wire, source_binding_from_wire, unavailable_reason_from_wire,
};

use crate::error::IngestError;

/// Longest binding name, in UTF-8 bytes.
pub const MAX_BINDING_NAME_BYTES: usize = 128;
/// Longest `ExceptionPayload.exception_type`, in bytes.
pub const MAX_EXCEPTION_TYPE_BYTES: usize = 256;
/// Longest `ExceptionPayload.sanitized_message`, in bytes.
pub const MAX_EXCEPTION_MESSAGE_BYTES: usize = 512;
/// Most tables on one interaction.
pub const MAX_INTERACTION_TABLES: usize = 16;
/// Longest table name, in bytes.
pub const MAX_TABLE_NAME_BYTES: usize = 128;
/// Longest `Interaction.sanitized_shape`, in bytes.
pub const MAX_SANITIZED_SHAPE_BYTES: usize = 512;
/// Longest `RuntimeFacts` string, in bytes.
pub const MAX_RUNTIME_FACT_BYTES: usize = 64;
/// Closed vocabulary for `Interaction.statement_kind`.
pub const STATEMENT_KINDS: [&str; 7] =
    ["select", "insert", "update", "delete", "ddl", "call", "other"];

/// Validates one event against the rules of its effective capture `mode`.
///
/// `audit_active` is whether the daemon audit redactor runs before storage; until it does, any
/// event carrying `bindings` is rejected with [`IngestError::BindingsNotAcceptedYet`] because XTF
/// segments are immutable and a persisted secret could never be downgraded.
///
/// # Errors
///
/// Returns the [`IngestError`] for the first violated rule.
pub fn validate_event(
    event: &RecordingEvent,
    mode: CaptureMode,
    audit_active: bool,
) -> Result<(), IngestError> {
    let seq = event.recording_seq;
    let budget = CaptureBudget::for_mode(mode);
    let kind = RecordingEventKind::try_from(event.kind)
        .map_err(|_| IngestError::UnknownEnumValue { recording_seq: seq, field: "kind" })?;
    let binding = source_binding_from_wire(event.source_binding)
        .ok_or(IngestError::UnknownEnumValue { recording_seq: seq, field: "source_binding" })?;

    check_source(event, binding)?;

    match kind {
        RecordingEventKind::LineCursor => {
            if budget.max_line_events == 0 {
                return Err(IngestError::LineEventNotAllowedInStandardMode { recording_seq: seq });
            }
            let single_line = event
                .source
                .as_ref()
                .is_some_and(|s| s.start_line > 0 && s.start_line == s.end_line);
            if !single_line || !binding.has_source_claim() {
                return Err(IngestError::LineCursorInvalid { recording_seq: seq });
            }
        }
        RecordingEventKind::FrameEnter
        | RecordingEventKind::FrameExit
        | RecordingEventKind::FrameThrow
            if event.symbol.is_empty() =>
        {
            return Err(IngestError::SymbolRequired { recording_seq: seq });
        }
        _ => {}
    }

    check_gap(event, kind)?;
    check_bindings(event, kind, &budget, audit_active)?;
    if let Some(value) = &event.value {
        check_free_value(seq, value)?;
    }
    if let Some(interaction) = &event.interaction {
        check_interaction(seq, interaction)?;
    }
    if let Some(exception) = &event.exception {
        check_exception(seq, exception)?;
    }
    Ok(())
}

fn check_source(event: &RecordingEvent, binding: SourceBinding) -> Result<(), IngestError> {
    let seq = event.recording_seq;
    match (event.source.as_ref(), binding.has_source_claim()) {
        (None, false) => Ok(()),
        (Some(_), false) | (None, true) => {
            Err(IngestError::SourceBindingMismatch { recording_seq: seq })
        }
        (Some(source), true) => {
            let hash_len = source.content_hash.len();
            let hash_ok = match binding {
                SourceBinding::Verified | SourceBinding::ObservedUnattested => hash_len == 32,
                _ => hash_len == 0 || hash_len == 32,
            };
            if !is_safe_repo_relative_path(&source.path)
                || !hash_ok
                || source.start_line == 0
                || (source.end_line != 0 && source.end_line < source.start_line)
            {
                return Err(IngestError::SourcePathInvalid { recording_seq: seq });
            }
            Ok(())
        }
    }
}

fn check_gap(event: &RecordingEvent, kind: RecordingEventKind) -> Result<(), IngestError> {
    let seq = event.recording_seq;
    match (kind == RecordingEventKind::Gap, event.gap.as_ref()) {
        (true, Some(gap)) => {
            // The golden coalesced-gap fixture (seq 4 describing 5..11) shows emitters may report
            // a range that is not below the GAP event's own seq, so only the range shape is
            // validated (first <= last, count > 0); CONTRACTS 7.1 needs that amendment.
            if !event.bindings.is_empty() || gap_from_wire(gap).is_err() {
                return Err(IngestError::GapPayloadInvalid { recording_seq: seq });
            }
            Ok(())
        }
        (true, None) | (false, Some(_)) => {
            Err(IngestError::GapPayloadInvalid { recording_seq: seq })
        }
        (false, None) => Ok(()),
    }
}

fn role_allowed(role: BindingRole, kind: RecordingEventKind) -> bool {
    match role {
        BindingRole::Argument | BindingRole::Receiver => kind == RecordingEventKind::FrameEnter,
        BindingRole::Return => kind == RecordingEventKind::FrameExit,
        BindingRole::Local => kind == RecordingEventKind::LineCursor,
        BindingRole::Exception => {
            kind == RecordingEventKind::FrameThrow || kind == RecordingEventKind::Exception
        }
    }
}

fn check_bindings(
    event: &RecordingEvent,
    kind: RecordingEventKind,
    budget: &CaptureBudget,
    audit_active: bool,
) -> Result<(), IngestError> {
    let seq = event.recording_seq;
    if event.bindings.is_empty() {
        return Ok(());
    }
    if !audit_active {
        return Err(IngestError::BindingsNotAcceptedYet { recording_seq: seq });
    }
    if event.bindings.len() > usize::from(budget.max_bindings_per_event) {
        return Err(IngestError::BindingsOverBudget { recording_seq: seq });
    }
    let mut value_bytes: usize = 0;
    let mut returns = 0_u32;
    for binding in &event.bindings {
        if binding.name.len() > MAX_BINDING_NAME_BYTES {
            return Err(IngestError::BindingNameTooLong { recording_seq: seq });
        }
        if binding.name.is_empty() || binding.name.chars().any(char::is_control) {
            return Err(IngestError::BindingNameInvalid { recording_seq: seq });
        }
        let role = binding_role_from_wire(binding.role)
            .ok_or(IngestError::UnknownEnumValue { recording_seq: seq, field: "binding.role" })?;
        name_origin_from_wire(binding.name_origin).ok_or(IngestError::UnknownEnumValue {
            recording_seq: seq,
            field: "binding.name_origin",
        })?;
        if role == BindingRole::Local && budget.max_line_events == 0 {
            return Err(IngestError::LocalsNotAllowedInStandardMode { recording_seq: seq });
        }
        if !role_allowed(role, kind) {
            return Err(IngestError::BindingRoleKindMismatch { recording_seq: seq });
        }
        if role == BindingRole::Return {
            returns += 1;
            if returns > 1 {
                return Err(IngestError::BindingRoleKindMismatch { recording_seq: seq });
            }
        }
        let value =
            binding.value.as_ref().ok_or(IngestError::ValueMissing { recording_seq: seq })?;
        let preview_bytes = check_value(seq, value, budget.max_preview_bytes)?;
        value_bytes = value_bytes.saturating_add(preview_bytes).saturating_add(binding.name.len());
    }
    if value_bytes > usize::try_from(budget.max_event_value_bytes).unwrap_or(usize::MAX) {
        return Err(IngestError::EventValueBytesOverBudget { recording_seq: seq });
    }
    Ok(())
}

/// Validates one binding value and returns its preview byte length.
fn check_value(
    seq: u64,
    value: &wire::CapturedValue,
    max_preview_bytes: u32,
) -> Result<usize, IngestError> {
    let max = usize::try_from(max_preview_bytes).unwrap_or(usize::MAX);
    match value.value.as_ref() {
        None => Err(IngestError::ValueMissing { recording_seq: seq }),
        Some(Value::Captured(captured)) => {
            if captured.preview.len() > max {
                return Err(IngestError::BindingPreviewTooLong { recording_seq: seq });
            }
            if captured.content_hash.len() != 32
                || captured.content_hash[..]
                    != *blake3::hash(captured.preview.as_bytes()).as_bytes()
            {
                return Err(IngestError::ContentHashInvalid { recording_seq: seq });
            }
            Ok(captured.preview.len())
        }
        Some(Value::Truncated(truncated)) => {
            if truncated.preview.len() > max {
                return Err(IngestError::BindingPreviewTooLong { recording_seq: seq });
            }
            Ok(truncated.preview.len())
        }
        Some(Value::Redacted(redacted)) => {
            if !rule_id_is_valid(&redacted.rule_id) {
                return Err(IngestError::RedactionRuleIdInvalid { recording_seq: seq });
            }
            Ok(0)
        }
        Some(Value::Unavailable(unavailable)) => {
            unavailable_reason_from_wire(unavailable.reason).ok_or(
                IngestError::UnknownEnumValue {
                    recording_seq: seq,
                    field: "binding.value.unavailable.reason",
                },
            )?;
            Ok(0)
        }
        Some(Value::Dropped(dropped)) => {
            drop_reason_from_wire(dropped.reason).ok_or(IngestError::UnknownEnumValue {
                recording_seq: seq,
                field: "binding.value.dropped.reason",
            })?;
            Ok(0)
        }
    }
}

/// Validates a value that is not a binding (`event.value`, interaction summaries and the finish
/// marker's response summary): the preview is bounded by the largest per-mode preview budget so the
/// audit redactor never scans an unbounded string, and a `Redacted` rule id keeps the pattern.
pub(crate) fn check_free_value(seq: u64, value: &wire::CapturedValue) -> Result<(), IngestError> {
    let max = usize::try_from(CaptureBudget::FOCUSED.max_preview_bytes).unwrap_or(usize::MAX);
    match value.value.as_ref() {
        Some(Value::Captured(c)) if c.preview.len() > max => {
            Err(IngestError::BindingPreviewTooLong { recording_seq: seq })
        }
        Some(Value::Truncated(t)) if t.preview.len() > max => {
            Err(IngestError::BindingPreviewTooLong { recording_seq: seq })
        }
        Some(Value::Redacted(r)) if !rule_id_is_valid(&r.rule_id) => {
            Err(IngestError::RedactionRuleIdInvalid { recording_seq: seq })
        }
        Some(Value::Unavailable(u)) if unavailable_reason_from_wire(u.reason).is_none() => {
            Err(IngestError::UnknownEnumValue {
                recording_seq: seq,
                field: "value.unavailable.reason",
            })
        }
        Some(Value::Dropped(d)) if drop_reason_from_wire(d.reason).is_none() => {
            Err(IngestError::UnknownEnumValue { recording_seq: seq, field: "value.dropped.reason" })
        }
        _ => Ok(()),
    }
}

/// Preview bytes one event adds to the recording's running value-byte total (binding previews,
/// `event.value` and interaction summaries). Redacted, unavailable and dropped values count zero.
#[must_use]
pub fn event_preview_bytes(event: &RecordingEvent) -> u64 {
    fn preview_len(value: &wire::CapturedValue) -> u64 {
        let len = match value.value.as_ref() {
            Some(Value::Captured(c)) => c.preview.len(),
            Some(Value::Truncated(t)) => t.preview.len(),
            _ => 0,
        };
        u64::try_from(len).unwrap_or(u64::MAX)
    }
    let mut total = event.bindings.iter().filter_map(|b| b.value.as_ref()).map(preview_len).sum();
    total += event.value.as_ref().map_or(0, preview_len);
    if let Some(interaction) = &event.interaction {
        for summary in [
            interaction.request_summary.as_ref(),
            interaction.response_summary.as_ref(),
            interaction.error.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            total += preview_len(summary);
        }
    }
    total
}

/// `^[a-z0-9_.:-]{1,64}$`
fn rule_id_is_valid(rule_id: &str) -> bool {
    !rule_id.is_empty()
        && rule_id.len() <= 64
        && rule_id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b':' | b'-')
        })
}

fn check_interaction(seq: u64, interaction: &wire::Interaction) -> Result<(), IngestError> {
    let bad = || IngestError::InteractionFieldInvalid { recording_seq: seq };
    if wire::InteractionKind::try_from(interaction.kind).is_err() {
        return Err(IngestError::UnknownEnumValue {
            recording_seq: seq,
            field: "interaction.kind",
        });
    }
    if !interaction.statement_kind.is_empty()
        && !STATEMENT_KINDS.contains(&interaction.statement_kind.as_str())
    {
        return Err(bad());
    }
    if interaction.tables.len() > MAX_INTERACTION_TABLES
        || interaction.tables.iter().any(|t| t.len() > MAX_TABLE_NAME_BYTES || has_control(t))
    {
        return Err(bad());
    }
    if interaction.sanitized_shape.len() > MAX_SANITIZED_SHAPE_BYTES
        || interaction.sanitized_shape.contains(['\'', '"', '`'])
    {
        return Err(bad());
    }
    for summary in [
        interaction.request_summary.as_ref(),
        interaction.response_summary.as_ref(),
        interaction.error.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        check_free_value(seq, summary)?;
    }
    if interaction.port > 65_535 {
        return Err(bad());
    }
    if interaction.status_code != 0 && !(100..=599).contains(&interaction.status_code) {
        return Err(bad());
    }
    if has_control(&interaction.path) {
        return Err(bad());
    }
    Ok(())
}

fn has_control(text: &str) -> bool {
    text.chars().any(char::is_control)
}

fn check_exception(seq: u64, exception: &wire::ExceptionPayload) -> Result<(), IngestError> {
    if exception.exception_type.len() > MAX_EXCEPTION_TYPE_BYTES
        || exception.sanitized_message.len() > MAX_EXCEPTION_MESSAGE_BYTES
    {
        return Err(IngestError::ExceptionFieldInvalid { recording_seq: seq });
    }
    Ok(())
}

/// Validates `RecordingFinished.outcome`, when present.
///
/// # Errors
///
/// Returns [`IngestError::OutcomeInvalid`] naming the first violated rule.
pub fn validate_finished(
    finished: &RecordingFinished,
    recording_id: xtrace_domain::RecordingId,
) -> Result<(), IngestError> {
    if let Some(summary) = &finished.response_summary {
        check_free_value(finished.final_recording_seq, summary)?;
    }
    if let Some(outcome) = &finished.outcome {
        outcome_from_wire(outcome)
            .map_err(|reason| IngestError::OutcomeInvalid { recording_id, reason })?;
    }
    Ok(())
}

/// Returns the started marker with an invalid `exercise_item_id` cleared.
///
/// The field must be canonical hyphenated UUID text; anything else is dropped (never stored) and
/// the recording is accepted without the link.
#[must_use]
pub fn normalize_started(started: &RecordingStarted) -> RecordingStarted {
    let mut normalized = started.clone();
    if !is_canonical_uuid(&normalized.exercise_item_id) {
        normalized.exercise_item_id.clear();
    }
    normalized
}

fn is_canonical_uuid(text: &str) -> bool {
    text.len() == 36 && Uuid::parse_str(text).is_ok()
}

/// Validates the adapter-reported runtime facts: every string at most 64 bytes with no control
/// characters.
///
/// # Errors
///
/// Returns [`IngestError::RuntimeFactsInvalid`] (with sequence 0, the hello carries none).
pub fn validate_runtime_facts(facts: &RuntimeFacts) -> Result<(), IngestError> {
    let fields = [
        &facts.framework,
        &facts.framework_version,
        &facts.module_system,
        &facts.launch_mode,
        &facts.capture_depth,
        &facts.node_mode,
        &facts.package_manager,
    ];
    if fields.iter().any(|f| f.len() > MAX_RUNTIME_FACT_BYTES || has_control(f)) {
        return Err(IngestError::RuntimeFactsInvalid { recording_seq: 0 });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use prost::bytes::Bytes;

    use super::*;

    const STD: CaptureMode = CaptureMode::Standard;
    const FOC: CaptureMode = CaptureMode::Focused;

    fn source(path: &str, line: u32, hash_len: usize) -> wire::SourceRange {
        wire::SourceRange {
            path: path.to_string(),
            start_line: line,
            start_column: 0,
            end_line: line,
            end_column: 0,
            content_hash: Bytes::from(vec![7_u8; hash_len]),
        }
    }

    fn base(kind: RecordingEventKind) -> RecordingEvent {
        RecordingEvent {
            recording_seq: 2,
            event_id: "e-2".to_string(),
            kind: kind as i32,
            symbol: "A.m".to_string(),
            ..RecordingEvent::default()
        }
    }

    fn line_event() -> RecordingEvent {
        RecordingEvent {
            source: Some(source("src/A.java", 10, 32)),
            source_binding: wire::SourceBinding::ObservedUnattested as i32,
            ..base(RecordingEventKind::LineCursor)
        }
    }

    fn captured(preview: &str) -> wire::CapturedValue {
        wire::CapturedValue {
            value: Some(Value::Captured(wire::CapturedValueCaptured {
                shape: wire::ValueShape::String as i32,
                preview: preview.to_string(),
                content_hash: Bytes::copy_from_slice(blake3::hash(preview.as_bytes()).as_bytes()),
            })),
        }
    }

    fn binding(
        name: &str,
        role: wire::BindingRole,
        value: wire::CapturedValue,
    ) -> wire::ValueBinding {
        wire::ValueBinding {
            name: name.to_string(),
            role: role as i32,
            name_origin: wire::NameOrigin::Declared as i32,
            value: Some(value),
        }
    }

    fn enter_with(bindings: Vec<wire::ValueBinding>) -> RecordingEvent {
        RecordingEvent { bindings, ..base(RecordingEventKind::FrameEnter) }
    }

    fn arg(name: &str, preview: &str) -> wire::ValueBinding {
        binding(name, wire::BindingRole::Argument, captured(preview))
    }

    fn check(event: &RecordingEvent, mode: CaptureMode) -> Result<(), IngestError> {
        validate_event(event, mode, true)
    }

    #[test]
    fn events_without_new_fields_validate_as_today() {
        let plain = RecordingEvent { recording_seq: 2, ..RecordingEvent::default() };
        assert!(check(&plain, STD).is_ok());
        assert!(check(&base(RecordingEventKind::FrameExit), STD).is_ok());
        assert!(check(&base(RecordingEventKind::ValueSnapshot), STD).is_ok());
    }

    #[test]
    fn line_event_requires_single_line_source() {
        assert!(check(&line_event(), FOC).is_ok());
        let mut multi = line_event();
        multi.source.as_mut().unwrap().end_line = 11;
        assert!(matches!(check(&multi, FOC), Err(IngestError::LineCursorInvalid { .. })));
        let zero = RecordingEvent { source: Some(source("src/A.java", 0, 32)), ..line_event() };
        assert!(matches!(check(&zero, FOC), Err(IngestError::SourcePathInvalid { .. })));
        let no_source = RecordingEvent { source: None, source_binding: 0, ..line_event() };
        assert!(matches!(check(&no_source, FOC), Err(IngestError::LineCursorInvalid { .. })));
    }

    #[test]
    fn line_event_in_standard_recording_rejected() {
        assert!(matches!(
            check(&line_event(), STD),
            Err(IngestError::LineEventNotAllowedInStandardMode { .. })
        ));
    }

    #[test]
    fn gap_event_requires_payload() {
        let bare = base(RecordingEventKind::Gap);
        assert!(matches!(check(&bare, STD), Err(IngestError::GapPayloadInvalid { .. })));
        let ok = RecordingEvent {
            gap: Some(wire::GapPayload {
                reason: wire::GapReason::LineBudget as i32,
                count: 7,
                first_recording_seq: 3,
                last_recording_seq: 9,
            }),
            recording_seq: 12,
            ..bare
        };
        assert!(check(&ok, STD).is_ok());
        // The range is not required to precede the GAP event's own seq (golden fixture).
        let mut early = ok.clone();
        early.recording_seq = 2;
        assert!(check(&early, STD).is_ok());
        let stray = RecordingEvent { gap: ok.gap, ..base(RecordingEventKind::FrameExit) };
        assert!(matches!(check(&stray, STD), Err(IngestError::GapPayloadInvalid { .. })));
    }

    #[test]
    fn gap_with_zero_count_rejected() {
        let mut gap = base(RecordingEventKind::Gap);
        gap.gap = Some(wire::GapPayload {
            reason: wire::GapReason::Throttle as i32,
            count: 0,
            ..wire::GapPayload::default()
        });
        assert!(matches!(check(&gap, STD), Err(IngestError::GapPayloadInvalid { .. })));
        gap.gap = Some(wire::GapPayload { reason: 0, count: 3, ..wire::GapPayload::default() });
        assert!(matches!(check(&gap, STD), Err(IngestError::GapPayloadInvalid { .. })));
        gap.gap = Some(wire::GapPayload {
            reason: 1,
            count: 3,
            first_recording_seq: 9,
            last_recording_seq: 3,
        });
        assert!(matches!(check(&gap, STD), Err(IngestError::GapPayloadInvalid { .. })));
    }

    #[test]
    fn binding_name_over_128_bytes_rejected() {
        let long = "n".repeat(129);
        assert!(matches!(
            check(&enter_with(vec![arg(&long, "v")]), STD),
            Err(IngestError::BindingNameTooLong { .. })
        ));
        assert!(check(&enter_with(vec![arg(&"n".repeat(128), "v")]), STD).is_ok());
        assert!(matches!(
            check(&enter_with(vec![arg("", "v")]), STD),
            Err(IngestError::BindingNameInvalid { .. })
        ));
        assert!(matches!(
            check(&enter_with(vec![arg("a\u{0}b", "v")]), STD),
            Err(IngestError::BindingNameInvalid { .. })
        ));
    }

    #[test]
    fn bindings_over_16_standard_rejected_32_focused_accepted() {
        let make =
            |n: usize| enter_with((0..n).map(|i| arg(&format!("a{i}"), "v")).collect::<Vec<_>>());
        assert!(check(&make(16), STD).is_ok());
        assert!(matches!(check(&make(17), STD), Err(IngestError::BindingsOverBudget { .. })));
        assert!(check(&make(32), FOC).is_ok());
        assert!(matches!(check(&make(33), FOC), Err(IngestError::BindingsOverBudget { .. })));
    }

    #[test]
    fn preview_over_512_bytes_rejected() {
        let ev = |n: usize| enter_with(vec![arg("a", &"p".repeat(n))]);
        assert!(check(&ev(512), FOC).is_ok());
        assert!(matches!(check(&ev(513), FOC), Err(IngestError::BindingPreviewTooLong { .. })));
    }

    #[test]
    fn preview_over_256_standard_rejected() {
        let ev = |n: usize| enter_with(vec![arg("a", &"p".repeat(n))]);
        assert!(check(&ev(256), STD).is_ok());
        assert!(matches!(check(&ev(257), STD), Err(IngestError::BindingPreviewTooLong { .. })));
    }

    #[test]
    fn event_value_bytes_over_budget_rejected() {
        // 16 bindings of 256-byte previews = 4096 + names (2 bytes each) > 4 KiB standard budget.
        let over = enter_with((0..16).map(|i| arg(&format!("{i:02}"), &"p".repeat(256))).collect());
        assert!(matches!(check(&over, STD), Err(IngestError::EventValueBytesOverBudget { .. })));
        let under =
            enter_with((0..15).map(|i| arg(&format!("{i:02}"), &"p".repeat(256))).collect());
        assert!(check(&under, STD).is_ok());
    }

    #[test]
    fn locals_in_standard_rejected() {
        let local = enter_with(vec![binding("x", wire::BindingRole::Local, captured("v"))]);
        assert!(matches!(
            check(&local, STD),
            Err(IngestError::LocalsNotAllowedInStandardMode { .. })
        ));
        let on_line = RecordingEvent {
            bindings: vec![binding("x", wire::BindingRole::Local, captured("v"))],
            ..line_event()
        };
        assert!(check(&on_line, FOC).is_ok());
    }

    #[test]
    fn binding_role_kind_matrix_enforced() {
        use RecordingEventKind as K;
        use wire::BindingRole as R;
        let allowed = [
            (R::Argument, K::FrameEnter),
            (R::Receiver, K::FrameEnter),
            (R::Return, K::FrameExit),
            (R::Exception, K::FrameThrow),
            (R::Exception, K::Exception),
        ];
        for (role, kind) in allowed {
            let ev =
                RecordingEvent { bindings: vec![binding("x", role, captured("v"))], ..base(kind) };
            assert!(check(&ev, FOC).is_ok(), "{role:?} on {kind:?}");
        }
        let denied = [
            (R::Argument, K::FrameExit),
            (R::Return, K::FrameEnter),
            (R::Receiver, K::FrameExit),
            (R::Exception, K::FrameEnter),
            (R::Argument, K::ValueSnapshot),
        ];
        for (role, kind) in denied {
            let ev =
                RecordingEvent { bindings: vec![binding("x", role, captured("v"))], ..base(kind) };
            assert!(
                matches!(check(&ev, FOC), Err(IngestError::BindingRoleKindMismatch { .. })),
                "{role:?} on {kind:?}"
            );
        }
        let two_returns = RecordingEvent {
            bindings: vec![
                binding("a", R::Return, captured("v")),
                binding("b", R::Return, captured("v")),
            ],
            ..base(K::FrameExit)
        };
        assert!(matches!(
            check(&two_returns, FOC),
            Err(IngestError::BindingRoleKindMismatch { .. })
        ));
    }

    #[test]
    fn free_value_unknown_reason_numbers_rejected() {
        let unavailable = wire::CapturedValue {
            value: Some(Value::Unavailable(wire::CapturedValueUnavailable { reason: 99 })),
        };
        assert!(matches!(
            check_free_value(2, &unavailable),
            Err(IngestError::UnknownEnumValue { .. })
        ));
        let dropped = wire::CapturedValue {
            value: Some(Value::Dropped(wire::CapturedValueDropped { reason: 99 })),
        };
        assert!(matches!(check_free_value(2, &dropped), Err(IngestError::UnknownEnumValue { .. })));
    }

    #[test]
    fn unknown_enum_value_rejected_not_coerced() {
        let mut ev = enter_with(vec![arg("a", "v")]);
        ev.bindings[0].role = 99;
        assert!(matches!(
            check(&ev, STD),
            Err(IngestError::UnknownEnumValue { field: "binding.role", .. })
        ));
        let mut ev = enter_with(vec![arg("a", "v")]);
        ev.bindings[0].role = 0;
        assert!(matches!(check(&ev, STD), Err(IngestError::UnknownEnumValue { .. })));
        let ev = RecordingEvent { source_binding: 42, ..base(RecordingEventKind::FrameEnter) };
        assert!(matches!(
            check(&ev, STD),
            Err(IngestError::UnknownEnumValue { field: "source_binding", .. })
        ));
        let ev = RecordingEvent { kind: 77, ..RecordingEvent::default() };
        assert!(matches!(
            check(&ev, STD),
            Err(IngestError::UnknownEnumValue { field: "kind", .. })
        ));
        let mut ev = enter_with(vec![arg("a", "v")]);
        ev.bindings[0].value = Some(wire::CapturedValue {
            value: Some(Value::Dropped(wire::CapturedValueDropped { reason: 42 })),
        });
        assert!(matches!(check(&ev, STD), Err(IngestError::UnknownEnumValue { .. })));
    }

    #[test]
    fn value_missing_rejected() {
        let mut ev = enter_with(vec![arg("a", "v")]);
        ev.bindings[0].value = None;
        assert!(matches!(check(&ev, STD), Err(IngestError::ValueMissing { .. })));
        ev.bindings[0].value = Some(wire::CapturedValue { value: None });
        assert!(matches!(check(&ev, STD), Err(IngestError::ValueMissing { .. })));
    }

    #[test]
    fn observed_unattested_source_requires_32_byte_hash() {
        for len in [0_usize, 31, 33] {
            let ev = RecordingEvent { source: Some(source("src/A.java", 4, len)), ..line_event() };
            assert!(
                matches!(check(&ev, FOC), Err(IngestError::SourcePathInvalid { .. })),
                "hash length {len}"
            );
        }
        assert!(check(&line_event(), FOC).is_ok());
    }

    #[test]
    fn source_map_absent_allows_empty_hash() {
        for binding in
            [wire::SourceBinding::SourceMapAbsent, wire::SourceBinding::SourceMapUnresolved]
        {
            let ev = RecordingEvent {
                source: Some(source("dist/app.js", 3, 0)),
                source_binding: binding as i32,
                ..base(RecordingEventKind::FrameEnter)
            };
            assert!(check(&ev, STD).is_ok(), "{binding:?}");
        }
    }

    #[test]
    fn non_fixture_repo_relative_path_accepted() {
        let ev = RecordingEvent {
            source: Some(source("services/billing/src/Invoice.kt", 12, 32)),
            source_binding: wire::SourceBinding::Verified as i32,
            ..base(RecordingEventKind::FrameEnter)
        };
        assert!(check(&ev, STD).is_ok());
    }

    #[test]
    fn path_traversal_absolute_backslash_empty_segment_rejected() {
        for bad in
            ["../x.java", "/abs/x.java", "a\\b.java", "a//b.java", "a/./b.java", "C:/x.java", ""]
        {
            let ev = RecordingEvent {
                source: Some(source(bad, 3, 32)),
                source_binding: wire::SourceBinding::Verified as i32,
                ..base(RecordingEventKind::FrameEnter)
            };
            assert!(
                matches!(check(&ev, STD), Err(IngestError::SourcePathInvalid { .. })),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn source_without_claiming_binding_rejected() {
        for binding in [
            wire::SourceBinding::Unspecified,
            wire::SourceBinding::AttestationMissing,
            wire::SourceBinding::ClassBytesMismatch,
        ] {
            let ev = RecordingEvent {
                source: Some(source("src/A.java", 3, 32)),
                source_binding: binding as i32,
                ..base(RecordingEventKind::FrameEnter)
            };
            assert!(
                matches!(check(&ev, STD), Err(IngestError::SourceBindingMismatch { .. })),
                "{binding:?}"
            );
        }
        let no_source = RecordingEvent {
            source_binding: wire::SourceBinding::Verified as i32,
            ..base(RecordingEventKind::FrameEnter)
        };
        assert!(matches!(check(&no_source, STD), Err(IngestError::SourceBindingMismatch { .. })));
    }

    #[test]
    fn rule_id_pattern_enforced() {
        let redacted = |rule: &str| wire::CapturedValue {
            value: Some(Value::Redacted(wire::CapturedValueRedacted {
                rule_id: rule.to_string(),
                shape_hint: 0,
            })),
        };
        for ok in ["name.secret", "daemon.audit", "a:b-c_d.9"] {
            let ev = enter_with(vec![binding("a", wire::BindingRole::Argument, redacted(ok))]);
            assert!(check(&ev, STD).is_ok(), "{ok}");
        }
        let too_long = "x".repeat(65);
        for bad in ["", "Upper", "has space", too_long.as_str()] {
            let ev = enter_with(vec![binding("a", wire::BindingRole::Argument, redacted(bad))]);
            assert!(
                matches!(check(&ev, STD), Err(IngestError::RedactionRuleIdInvalid { .. })),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn statement_kind_closed_enum() {
        let with = |kind: &str| RecordingEvent {
            interaction: Some(wire::Interaction {
                kind: wire::InteractionKind::Database as i32,
                statement_kind: kind.to_string(),
                ..wire::Interaction::default()
            }),
            ..base(RecordingEventKind::DatabaseStart)
        };
        for kind in STATEMENT_KINDS {
            assert!(check(&with(kind), STD).is_ok(), "{kind}");
        }
        assert!(check(&with(""), STD).is_ok(), "absent statement kind is allowed");
        assert!(matches!(
            check(&with("merge"), STD),
            Err(IngestError::InteractionFieldInvalid { .. })
        ));
    }

    #[test]
    fn sanitized_shape_with_quote_rejected() {
        let with = |shape: &str| RecordingEvent {
            interaction: Some(wire::Interaction {
                sanitized_shape: shape.to_string(),
                ..wire::Interaction::default()
            }),
            ..base(RecordingEventKind::DatabaseStart)
        };
        assert!(check(&with("select * from t where id = ?"), STD).is_ok());
        for bad in ["where n = 'x'", "where n = \"x\"", "where n = `x`"] {
            assert!(
                matches!(check(&with(bad), STD), Err(IngestError::InteractionFieldInvalid { .. })),
                "{bad}"
            );
        }
        assert!(matches!(
            check(&with(&"?".repeat(513)), STD),
            Err(IngestError::InteractionFieldInvalid { .. })
        ));
    }

    #[test]
    fn interaction_tables_port_and_status_are_bounded() {
        let with = |tables: Vec<String>, port: u32, status: u32| RecordingEvent {
            interaction: Some(wire::Interaction {
                tables,
                port,
                status_code: status,
                ..wire::Interaction::default()
            }),
            ..base(RecordingEventKind::OutboundHttpEnd)
        };
        assert!(check(&with(vec!["t".to_string(); 16], 443, 200), STD).is_ok());
        for bad in [
            with(vec!["t".to_string(); 17], 0, 0),
            with(vec!["t".repeat(129)], 0, 0),
            with(Vec::new(), 70_000, 0),
            with(Vec::new(), 0, 99),
            with(Vec::new(), 0, 600),
        ] {
            assert!(matches!(check(&bad, STD), Err(IngestError::InteractionFieldInvalid { .. })));
        }
    }

    #[test]
    fn captured_empty_hash_rejected() {
        let mut value = captured("v");
        if let Some(Value::Captured(c)) = value.value.as_mut() {
            c.content_hash = Bytes::new();
        }
        let ev = enter_with(vec![binding("a", wire::BindingRole::Argument, value)]);
        assert!(matches!(check(&ev, STD), Err(IngestError::ContentHashInvalid { .. })));
    }

    #[test]
    fn captured_hash_must_match_preview_blake3() {
        let mut value = captured("v");
        if let Some(Value::Captured(c)) = value.value.as_mut() {
            c.content_hash = Bytes::from(vec![9_u8; 32]);
        }
        let ev = enter_with(vec![binding("a", wire::BindingRole::Argument, value)]);
        assert!(matches!(check(&ev, STD), Err(IngestError::ContentHashInvalid { .. })));
    }

    #[test]
    fn bindings_rejected_until_audit_active() {
        let ev = enter_with(vec![arg("a", "v")]);
        assert!(matches!(
            validate_event(&ev, STD, false),
            Err(IngestError::BindingsNotAcceptedYet { .. })
        ));
        assert!(validate_event(&ev, STD, true).is_ok());
        let plain = base(RecordingEventKind::FrameEnter);
        assert!(
            validate_event(&plain, STD, false).is_ok(),
            "events without bindings are unaffected"
        );
    }

    #[test]
    fn frame_events_require_a_symbol() {
        for kind in [
            RecordingEventKind::FrameEnter,
            RecordingEventKind::FrameExit,
            RecordingEventKind::FrameThrow,
        ] {
            let ev = RecordingEvent { symbol: String::new(), ..base(kind) };
            assert!(matches!(check(&ev, STD), Err(IngestError::SymbolRequired { .. })), "{kind:?}");
        }
    }

    #[test]
    fn exception_payload_bounds() {
        let with = |ty: usize, msg: usize| RecordingEvent {
            exception: Some(wire::ExceptionPayload {
                exception_type: "t".repeat(ty),
                sanitized_message: "m".repeat(msg),
                stack_frames: Vec::new(),
            }),
            ..base(RecordingEventKind::Exception)
        };
        assert!(check(&with(256, 512), STD).is_ok());
        assert!(matches!(
            check(&with(257, 0), STD),
            Err(IngestError::ExceptionFieldInvalid { .. })
        ));
        assert!(matches!(
            check(&with(0, 513), STD),
            Err(IngestError::ExceptionFieldInvalid { .. })
        ));
    }

    #[test]
    fn finished_outcome_rules() {
        let id = xtrace_domain::RecordingId::new();
        let finished = |outcome: Option<wire::RecordingOutcome>| RecordingFinished {
            outcome,
            ..RecordingFinished::default()
        };
        assert!(validate_finished(&finished(None), id).is_ok(), "no outcome is legal");
        let responded = wire::RecordingOutcome {
            kind: wire::OutcomeKind::Responded as i32,
            http_status: 200,
            ..wire::RecordingOutcome::default()
        };
        assert!(validate_finished(&finished(Some(responded.clone())), id).is_ok());
        // exception present iff EXCEPTION_PROPAGATED
        let missing = wire::RecordingOutcome {
            kind: wire::OutcomeKind::ExceptionPropagated as i32,
            ..wire::RecordingOutcome::default()
        };
        assert!(matches!(
            validate_finished(&finished(Some(missing)), id),
            Err(IngestError::OutcomeInvalid { .. })
        ));
        // UNOBSERVED requires status 0
        let unobserved = wire::RecordingOutcome {
            kind: wire::OutcomeKind::Unobserved as i32,
            http_status: 200,
            ..wire::RecordingOutcome::default()
        };
        assert!(matches!(
            validate_finished(&finished(Some(unobserved)), id),
            Err(IngestError::OutcomeInvalid { reason: "unobserved_with_status", .. })
        ));
        // unspecified kind, bad status, oversize message
        assert!(validate_finished(&finished(Some(wire::RecordingOutcome::default())), id).is_err());
        let bad_status = wire::RecordingOutcome { http_status: 700, ..responded };
        assert!(validate_finished(&finished(Some(bad_status)), id).is_err());
        let long = wire::RecordingOutcome {
            kind: wire::OutcomeKind::ExceptionPropagated as i32,
            exception: Some(wire::ExceptionPayload {
                exception_type: "E".to_string(),
                sanitized_message: "m".repeat(513),
                stack_frames: Vec::new(),
            }),
            ..wire::RecordingOutcome::default()
        };
        assert!(validate_finished(&finished(Some(long)), id).is_err());
    }

    #[test]
    fn exercise_item_id_valid_uuid_kept_invalid_cleared() {
        let started = |id: &str| RecordingStarted {
            exercise_item_id: id.to_string(),
            ..RecordingStarted::default()
        };
        let good = "6f1c1d0e-8b8e-4c52-9a43-0f6f2d9b7a10";
        assert_eq!(normalize_started(&started(good)).exercise_item_id, good);
        for bad in [
            "not-a-uuid",
            "6f1c1d0e8b8e4c529a430f6f2d9b7a10",
            "{6f1c1d0e-8b8e-4c52-9a43-0f6f2d9b7a10}",
            "",
        ] {
            assert!(normalize_started(&started(bad)).exercise_item_id.is_empty(), "{bad}");
        }
    }

    #[test]
    fn runtime_facts_string_bounds() {
        let facts = |framework: &str| RuntimeFacts {
            framework: framework.to_string(),
            ..RuntimeFacts::default()
        };
        assert!(validate_runtime_facts(&facts(&"f".repeat(64))).is_ok());
        assert!(validate_runtime_facts(&facts(&"f".repeat(65))).is_err());
        assert!(validate_runtime_facts(&facts("a\nb")).is_err());
    }

    #[test]
    fn new_ingest_errors_not_session_fatal() {
        let errors = [
            IngestError::BindingsOverBudget { recording_seq: 1 },
            IngestError::BindingNameTooLong { recording_seq: 1 },
            IngestError::BindingPreviewTooLong { recording_seq: 1 },
            IngestError::EventValueBytesOverBudget { recording_seq: 1 },
            IngestError::ValueMissing { recording_seq: 1 },
            IngestError::UnknownEnumValue { recording_seq: 1, field: "x" },
            IngestError::LineCursorInvalid { recording_seq: 1 },
            IngestError::LineEventNotAllowedInStandardMode { recording_seq: 1 },
            IngestError::LocalsNotAllowedInStandardMode { recording_seq: 1 },
            IngestError::GapPayloadInvalid { recording_seq: 1 },
            IngestError::OutcomeInvalid {
                recording_id: xtrace_domain::RecordingId::new(),
                reason: "x",
            },
            IngestError::HashOnRedacted { recording_seq: 1 },
            IngestError::SourceBindingMismatch { recording_seq: 1 },
            IngestError::BindingRoleKindMismatch { recording_seq: 1 },
            IngestError::BindingsNotAcceptedYet { recording_seq: 1 },
            IngestError::RedactionRuleIdInvalid { recording_seq: 1 },
            IngestError::InteractionFieldInvalid { recording_seq: 1 },
        ];
        for error in errors {
            assert!(!error.is_session_fatal(), "{error}");
        }
    }
}
