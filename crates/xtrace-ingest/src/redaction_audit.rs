//! Daemon-side audit redactor (CONTRACTS section 9.3, FR-2).
//!
//! A second pass the daemon runs on every accepted event before storage, so a secret the adapter
//! failed to redact never reaches an immutable XTF segment. The audit can only make a value safer:
//! it downgrades `Captured` and `Truncated` values to `Redacted { rule_id: "daemon.audit" }` and
//! replaces matching free text with a marker. It never upgrades a value, never reads a file and
//! performs no I/O.
//!
//! The rules (all deterministic, no regex engine):
//! - name rule: a binding name containing a secret word (`password`, `token`, ...), compared
//!   lowercase with `_ - .` removed, makes the whole value `Redacted`;
//! - content rules: a JWT-shaped token, an AWS access key id (`AKIA` plus 16 upper-case
//!   alphanumerics), a PEM block header, and `Bearer <token>`.

use blake3::Hasher;
use xtrace_protocol::generated::agent::{
    CapturedValue, CapturedValueRedacted, RecordingEvent, RecordingFinished, ValueShape,
    captured_value::Value,
};

/// Rule id stamped on every value the audit downgrades.
pub const AUDIT_RULE_ID: &str = "daemon.audit";
/// Version string of the audit policy, recorded with the policy digest.
pub const AUDIT_POLICY_VERSION: &str = "xtrace.audit.v1";
/// Marker that replaces matching free text.
pub const AUDIT_TEXT_MARKER: &str = "[redacted:daemon.audit]";

/// Words that mark a binding name as secret-bearing (compared lowercase, separators removed).
const SECRET_NAME_WORDS: [&str; 15] = [
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "authorization",
    "credential",
    "privatekey",
    "cookie",
    "session",
    "bearer",
    "accesskey",
    "signature",
];

/// What one audit pass changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditReport {
    /// Values downgraded to `Redacted`.
    pub downgraded_values: usize,
    /// Free-text fields whose matching text was replaced with the marker.
    pub redacted_text_fields: usize,
}

impl AuditReport {
    /// Returns `true` when the audit changed nothing.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.downgraded_values == 0 && self.redacted_text_fields == 0
    }
}

/// Digest of the audit policy (version plus the rule words), recorded against the recording's
/// `redaction_policy_digest` so a reader can tell which audit ran.
#[must_use]
pub fn audit_policy_digest() -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(AUDIT_POLICY_VERSION.as_bytes());
    for word in SECRET_NAME_WORDS {
        hasher.update(b"|name:");
        hasher.update(word.as_bytes());
    }
    hasher.update(b"|content:jwt|content:akia|content:pem|content:bearer");
    *hasher.finalize().as_bytes()
}

/// Returns `true` when a binding or field name looks secret-bearing.
#[must_use]
pub fn name_is_secret(name: &str) -> bool {
    let normalized: String = name
        .chars()
        .filter(|c| !matches!(c, '_' | '-' | '.' | ' '))
        .flat_map(char::to_lowercase)
        .collect();
    SECRET_NAME_WORDS.iter().any(|word| normalized.contains(word))
}

/// Returns `true` when `text` contains a secret by content.
#[must_use]
pub fn text_has_secret(text: &str) -> bool {
    contains_jwt(text)
        || contains_aws_key(text)
        || text.contains("-----BEGIN ")
        || contains_bearer(text)
}

/// `eyJ<b64>.<b64>.<b64>` where each part is at least 4 bytes.
///
/// Linear in the text length: the text is split once into runs of base64url characters and dots,
/// and each run is walked part by part with a two-part window, so no candidate is rescanned and
/// nothing is allocated (a 1 MiB run of `eyJ` costs one pass).
fn contains_jwt(text: &str) -> bool {
    for run in text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))) {
        // `head_prev`: the previous part contains `eyJ` followed by at least one more byte (the
        // earliest occurrence leaves the longest header, so it dominates later ones).
        // `window`: the part before the previous one is such a head and the previous part is
        // at least 4 bytes, so a current part of at least 4 bytes completes a token.
        let mut head_prev = false;
        let mut window = false;
        for part in run.split('.') {
            if window && part.len() >= 4 {
                return true;
            }
            window = head_prev && part.len() >= 4;
            head_prev = part.find("eyJ").is_some_and(|at| part.len() - at >= 4);
        }
    }
    false
}

fn contains_aws_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut start = 0;
    while let Some(offset) = text[start..].find("AKIA") {
        let begin = start + offset;
        let tail = &bytes[begin + 4..];
        if tail.len() >= 16
            && tail[..16].iter().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            return true;
        }
        start = begin + 4;
    }
    false
}

/// `Bearer ` followed by a token of at least 8 token characters.
fn contains_bearer(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let mut start = 0;
    while let Some(offset) = lower[start..].find("bearer ") {
        let begin = start + offset + 7;
        let token_len = lower.as_bytes()[begin..]
            .iter()
            .copied()
            .take_while(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(*b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
            })
            .count();
        if token_len >= 8 {
            return true;
        }
        start = begin;
    }
    false
}

/// Replaces `text` with the marker when it contains a secret. Returns `true` when it did.
fn scrub_text(text: &mut String) -> bool {
    if text_has_secret(text) {
        *text = AUDIT_TEXT_MARKER.to_string();
        true
    } else {
        false
    }
}

fn shape_hint(value: &Value) -> i32 {
    match value {
        Value::Captured(c) => c.shape,
        Value::Redacted(r) => r.shape_hint,
        _ => ValueShape::Unspecified as i32,
    }
}

fn redacted_marker(shape_hint: i32) -> Value {
    Value::Redacted(CapturedValueRedacted { rule_id: AUDIT_RULE_ID.to_string(), shape_hint })
}

/// Audits one value. `force` downgrades it regardless of content (a secret-named binding).
/// Returns `true` when the value was downgraded.
fn audit_value(value: &mut CapturedValue, force: bool) -> bool {
    let Some(inner) = value.value.as_mut() else {
        return false;
    };
    let preview = match inner {
        Value::Captured(c) => Some(c.preview.as_str()),
        Value::Truncated(t) => Some(t.preview.as_str()),
        _ => None,
    };
    let Some(preview) = preview else {
        return false;
    };
    if force || text_has_secret(preview) {
        let hint = shape_hint(inner);
        *inner = redacted_marker(hint);
        true
    } else {
        false
    }
}

/// Audits one event in place: binding values (by name and by content), the single value,
/// interaction summaries, exception text and the sanitized statement shape.
pub fn audit_event(event: &mut RecordingEvent) -> AuditReport {
    let mut report = AuditReport::default();
    for binding in &mut event.bindings {
        if scrub_text(&mut binding.name) {
            // The name itself was a secret; its value cannot be trusted either.
            report.redacted_text_fields += 1;
            if binding.value.as_mut().is_some_and(|value| audit_value(value, true)) {
                report.downgraded_values += 1;
            }
            continue;
        }
        let secret_name = name_is_secret(&binding.name);
        if binding.value.as_mut().is_some_and(|value| audit_value(value, secret_name)) {
            report.downgraded_values += 1;
        }
    }
    if event.value.as_mut().is_some_and(|value| audit_value(value, false)) {
        report.downgraded_values += 1;
    }
    if let Some(interaction) = event.interaction.as_mut() {
        for summary in [
            interaction.request_summary.as_mut(),
            interaction.response_summary.as_mut(),
            interaction.error.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            if audit_value(summary, false) {
                report.downgraded_values += 1;
            }
        }
        if scrub_text(&mut interaction.sanitized_shape) {
            report.redacted_text_fields += 1;
        }
    }
    if event.exception.as_mut().is_some_and(|e| scrub_text(&mut e.sanitized_message)) {
        report.redacted_text_fields += 1;
    }
    report
}

/// Audits a finish marker in place: the response summary and the outcome exception message.
pub fn audit_finished(finished: &mut RecordingFinished) -> AuditReport {
    let mut report = AuditReport::default();
    if finished.response_summary.as_mut().is_some_and(|summary| audit_value(summary, false)) {
        report.downgraded_values += 1;
    }
    let outcome_exception = finished.outcome.as_mut().and_then(|o| o.exception.as_mut());
    if outcome_exception.is_some_and(|e| scrub_text(&mut e.sanitized_message)) {
        report.redacted_text_fields += 1;
    }
    report
}

#[cfg(test)]
mod tests {
    use prost::Message as _;
    use prost::bytes::Bytes;
    use xtrace_protocol::generated::agent as wire;

    use super::*;

    const JWT: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    fn captured(preview: &str) -> wire::CapturedValue {
        wire::CapturedValue {
            value: Some(Value::Captured(wire::CapturedValueCaptured {
                shape: ValueShape::String as i32,
                preview: preview.to_string(),
                content_hash: Bytes::copy_from_slice(blake3::hash(preview.as_bytes()).as_bytes()),
            })),
        }
    }

    fn binding(name: &str, value: wire::CapturedValue) -> wire::ValueBinding {
        wire::ValueBinding {
            name: name.to_string(),
            role: wire::BindingRole::Argument as i32,
            name_origin: wire::NameOrigin::Declared as i32,
            value: Some(value),
        }
    }

    fn event_with(bindings: Vec<wire::ValueBinding>) -> RecordingEvent {
        RecordingEvent { recording_seq: 2, bindings, ..RecordingEvent::default() }
    }

    fn is_audit_redacted(binding: &wire::ValueBinding) -> bool {
        matches!(
            binding.value.as_ref().and_then(|v| v.value.as_ref()),
            Some(Value::Redacted(r)) if r.rule_id == AUDIT_RULE_ID
        )
    }

    #[test]
    fn name_secret_value_downgraded() {
        let mut event = event_with(vec![
            binding("password", captured("hunter2")),
            binding("user_token", captured("abc")),
            binding("Api-Key", captured("k")),
            binding("owner", captured("Ada")),
            binding("pwd", captured("hunter2")),
            binding("session", captured("JSESSIONID-value")),
        ]);
        let report = audit_event(&mut event);
        assert_eq!(report.downgraded_values, 5);
        assert!(is_audit_redacted(&event.bindings[4]), "pwd is a secret name (ADR 0003 6.2)");
        assert!(is_audit_redacted(&event.bindings[5]), "session is a secret name (ADR 0003 6.2)");
        assert!(is_audit_redacted(&event.bindings[0]));
        assert!(is_audit_redacted(&event.bindings[1]));
        assert!(is_audit_redacted(&event.bindings[2]));
        assert!(!is_audit_redacted(&event.bindings[3]), "an ordinary name stays captured");
    }

    #[test]
    fn jwt_scan_is_linear_on_adversarial_input() {
        // 256 KiB of overlapping `eyJ` candidates: the old per-candidate rescan was quadratic.
        let text = "eyJ".repeat(256 * 1024 / 3);
        let started = std::time::Instant::now();
        assert!(!text_has_secret(&text));
        let mixed = format!("{}{JWT}", "eyJ.".repeat(64 * 1024));
        assert!(text_has_secret(&mixed), "a real token after the noise is still found");
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "scan must stay linear");
    }

    #[test]
    fn jwt_shapes_match_the_old_rule() {
        assert!(contains_jwt("eyJa.bbbb.cccc"));
        assert!(contains_jwt("xx eyJhbGciOi.payload.sig_x end"));
        assert!(!contains_jwt("eyJ.bbbb.cccc"), "header needs at least 4 bytes from eyJ");
        assert!(!contains_jwt("eyJhbGc.bbb.cccc"), "payload under 4 bytes");
        assert!(!contains_jwt("eyJhbGc.bbbb"), "two parts only");
        assert!(!contains_jwt("eyJhbGc..cccc"), "empty middle part");
    }

    #[test]
    fn jwt_preview_downgraded() {
        let mut event = event_with(vec![binding("x", captured(&format!("auth={JWT}")))]);
        assert_eq!(audit_event(&mut event).downgraded_values, 1);
        assert!(is_audit_redacted(&event.bindings[0]));
    }

    #[test]
    fn content_rules_cover_aws_pem_and_bearer() {
        for secret in [
            "id AKIAIOSFODNN7EXAMPLE end",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE",
            "Authorization: Bearer abcdefgh12345678",
            "bearer ZXlKaGJHY2lPaUpJVXpJMU5pSjk",
        ] {
            assert!(text_has_secret(secret), "{secret}");
            let mut event = event_with(vec![binding("note", captured(secret))]);
            assert_eq!(audit_event(&mut event).downgraded_values, 1, "{secret}");
        }
        for fine in ["AKIA short", "eyJ.a.b", "bearer short", "plain text", "Bearer"] {
            assert!(!text_has_secret(fine), "{fine}");
        }
    }

    #[test]
    fn audit_never_upgrades() {
        let redacted = wire::CapturedValue {
            value: Some(Value::Redacted(CapturedValueRedacted {
                rule_id: "name.secret".to_string(),
                shape_hint: ValueShape::String as i32,
            })),
        };
        let unavailable = wire::CapturedValue {
            value: Some(Value::Unavailable(wire::CapturedValueUnavailable {
                reason: wire::UnavailableReason::FocusedCaptureNotArmed as i32,
            })),
        };
        let dropped = wire::CapturedValue {
            value: Some(Value::Dropped(wire::CapturedValueDropped {
                reason: wire::DropReason::ValueBudget as i32,
            })),
        };
        let mut event = event_with(vec![
            binding("a", redacted.clone()),
            binding("b", unavailable.clone()),
            binding("c", dropped.clone()),
            binding("d", captured("fine")),
        ]);
        let before = event.clone();
        let report = audit_event(&mut event);
        assert!(report.is_clean());
        assert_eq!(event, before, "an already safe event is returned untouched");
        assert_eq!(event.bindings[0].value, Some(redacted), "the original rule id is kept");
    }

    #[test]
    fn exception_outcome_and_shape_text_are_scrubbed() {
        let mut event = RecordingEvent {
            exception: Some(wire::ExceptionPayload {
                exception_type: "E".to_string(),
                sanitized_message: format!("failed with {JWT}"),
                stack_frames: Vec::new(),
            }),
            interaction: Some(wire::Interaction {
                sanitized_shape: "select 'AKIAIOSFODNN7EXAMPLE'".to_string(),
                ..wire::Interaction::default()
            }),
            ..RecordingEvent::default()
        };
        let report = audit_event(&mut event);
        assert_eq!(report.redacted_text_fields, 2);
        assert_eq!(event.exception.as_ref().unwrap().sanitized_message, AUDIT_TEXT_MARKER);

        let mut finished = RecordingFinished {
            outcome: Some(wire::RecordingOutcome {
                kind: wire::OutcomeKind::ExceptionPropagated as i32,
                exception: Some(wire::ExceptionPayload {
                    exception_type: "E".to_string(),
                    sanitized_message: "Authorization: Bearer abcdefgh12345678".to_string(),
                    stack_frames: Vec::new(),
                }),
                ..wire::RecordingOutcome::default()
            }),
            ..RecordingFinished::default()
        };
        assert_eq!(audit_finished(&mut finished).redacted_text_fields, 1);
    }

    #[test]
    fn secret_named_binding_name_is_replaced_and_value_downgraded() {
        let mut event = event_with(vec![binding(JWT, captured("v"))]);
        let report = audit_event(&mut event);
        assert_eq!(report.redacted_text_fields, 1);
        assert_eq!(report.downgraded_values, 1);
        assert_eq!(event.bindings[0].name, AUDIT_TEXT_MARKER);
    }

    #[test]
    fn canary_absent_from_encoded_event_bytes() {
        let canary = "CANARY-7f3a91";
        let mut event = event_with(vec![
            binding("password", captured(canary)),
            binding("note", captured(&format!("token Bearer {canary}{canary}"))),
        ]);
        event.exception = Some(wire::ExceptionPayload {
            exception_type: "E".to_string(),
            sanitized_message: format!("Bearer {canary}{canary}"),
            stack_frames: Vec::new(),
        });
        audit_event(&mut event);
        let bytes = event.encode_to_vec();
        let needle = canary.as_bytes();
        assert!(!bytes.windows(needle.len()).any(|w| w == needle), "canary leaked into the bytes");
    }

    #[test]
    fn policy_digest_is_stable_and_versioned() {
        assert_eq!(audit_policy_digest(), audit_policy_digest());
        assert_ne!(audit_policy_digest(), [0_u8; 32]);
    }
}
