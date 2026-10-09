//! The checked-in honesty strings (`schema/fixtures/replay/honesty-strings.json`) cover exactly the
//! stable codes the domain defines, so a client can always look up text for a code it receives.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration tests assert on fixture data and fail by panicking"
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;
use xtrace_domain::{
    DropReason, GapReason, HonestyMarker, OutcomeKind, SourceBinding, UnavailableReason,
};

fn fixture() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../schema/fixtures/replay/honesty-strings.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("read honesty strings"))
        .expect("honesty strings json")
}

fn keys(doc: &Value, section: &str) -> BTreeSet<String> {
    doc[section].as_object().expect("section object").keys().cloned().collect()
}

fn set(codes: &[&str]) -> BTreeSet<String> {
    codes.iter().map(|c| (*c).to_string()).collect()
}

#[test]
fn honesty_strings_cover_every_stable_code() {
    let doc = fixture();
    assert_eq!(doc["schemaVersion"], 1);
    assert_eq!(
        keys(&doc, "markers"),
        set(&HonestyMarker::ALL.map(HonestyMarker::as_str)),
        "markers"
    );
    assert_eq!(
        keys(&doc, "sourceBindings"),
        set(&[
            SourceBinding::Unspecified,
            SourceBinding::Verified,
            SourceBinding::AttestationMissing,
            SourceBinding::ClassBytesMismatch,
            SourceBinding::DebugMetadataAbsent,
            SourceBinding::SourceMetadataInvalid,
            SourceBinding::ObservedUnattested,
            SourceBinding::SourceMapAbsent,
            SourceBinding::SourceMapUnresolved,
        ]
        .map(SourceBinding::as_str)),
        "sourceBindings"
    );
    assert_eq!(
        keys(&doc, "unavailableReasons"),
        set(&[
            UnavailableReason::CapabilityUnsupported,
            UnavailableReason::DebugMetadataAbsent,
            UnavailableReason::CaptureBudgetExhausted,
            UnavailableReason::SourceArtifactMissing,
            UnavailableReason::RecorderDisconnected,
            UnavailableReason::PrivacyPolicyUnavailable,
            UnavailableReason::FocusedCaptureNotArmed,
            UnavailableReason::UnsafeToRender,
            UnavailableReason::ClassNotTransformable,
        ]
        .map(UnavailableReason::as_str)),
        "unavailableReasons"
    );
    assert_eq!(
        keys(&doc, "dropReasons"),
        set(&[
            DropReason::BackpressureShed,
            DropReason::QueueFull,
            DropReason::SequenceGap,
            DropReason::AdapterDropped,
            DropReason::ThrottleSuppressed,
            DropReason::LineBudget,
            DropReason::ValueBudget,
        ]
        .map(DropReason::as_str)),
        "dropReasons"
    );
    assert_eq!(
        keys(&doc, "gapReasons"),
        set(&[
            GapReason::LineBudget,
            GapReason::ValueBudget,
            GapReason::Throttle,
            GapReason::QueueFull,
            GapReason::CorrelationLost,
            GapReason::ClassNotTransformed,
            GapReason::ModuleLoadedBeforeArm,
            GapReason::SourceMapAbsent,
            GapReason::HandledExceptionUnobserved,
            GapReason::ChildProcessNotInstrumented,
            GapReason::BootstrapConsumed,
        ]
        .map(GapReason::as_str)),
        "gapReasons"
    );
    assert_eq!(
        keys(&doc, "outcomeKinds"),
        set(&[
            OutcomeKind::Responded,
            OutcomeKind::ExceptionPropagated,
            OutcomeKind::ClientAborted,
            OutcomeKind::Unobserved,
        ]
        .map(OutcomeKind::as_str)),
        "outcomeKinds"
    );
}

#[test]
fn honesty_text_never_claims_code_did_not_run() {
    let doc = fixture();
    let text = serde_json::to_string(&doc).expect("render").to_lowercase();
    for banned in ["did not run", "never ran", "was not executed", "skipped"] {
        assert!(!text.contains(banned), "honesty text must say 'not observed', found {banned:?}");
    }
}
