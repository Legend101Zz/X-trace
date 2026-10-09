//! Provenance and evidence types.
//!
//! X-trace never conflates static inference, runtime discovery, and
//! observed executions. Every durable claim carries a [`ProvenanceKind`]
//! and an [`EvidenceRef`] describing how it was produced.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash::ContentHash;
use crate::ids::{RecordingId, RuntimeSessionId, SourceRevisionId};

/// Coarse provenance classification shared by catalog entries, frames,
/// and evidence references.
///
/// The order in this enum is meaningful for reconciliation: higher
/// provenance outranks lower provenance when ranking runtime handler
/// identity. See `03a-domain-and-storage.md` §5 for the exact ranking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceKind {
    /// Static analysis inferred the path is possible. Never implies
    /// execution.
    StaticInferred,
    /// A live framework registered the endpoint or handler but it has
    /// not executed.
    RuntimeDiscovered,
    /// An instrumented request produced the evidence.
    Observed,
    /// Capture began but data was dropped, unsupported, or ended early.
    PartialObservation,
    /// An imported OpenAPI or Postman artifact contributed the claim.
    ImportedSpec,
    /// A user-declared project configuration contributed the claim.
    UserDeclared,
}

impl ProvenanceKind {
    /// Returns the wire string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaticInferred => "static_inferred",
            Self::RuntimeDiscovered => "runtime_discovered",
            Self::Observed => "observed",
            Self::PartialObservation => "partial_observation",
            Self::ImportedSpec => "imported_spec",
            Self::UserDeclared => "user_declared",
        }
    }

    /// Returns `true` if the provenance implies an executed recording.
    ///
    /// Only `Observed` and `PartialObservation` are tied to a recording.
    /// The other variants are catalog or hypothesis artifacts and cannot
    /// contribute replay frames.
    #[must_use]
    pub const fn is_recording_backed(self) -> bool {
        matches!(self, Self::Observed | Self::PartialObservation)
    }
}

impl fmt::Display for ProvenanceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Identity of the producer that emitted an evidence item.
///
/// Producers are scoped by language and runtime; they are not user data
/// and therefore do not pass through the privacy redaction pipeline.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProducerIdentity {
    /// Language tag (`java`, `node`, `rust`, ...).
    pub language: String,
    /// Adapter name as declared in the language pack manifest.
    pub adapter: String,
    /// Adapter version.
    pub adapter_version: String,
    /// Runtime or build version.
    pub runtime_version: String,
}

impl fmt::Debug for ProducerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProducerIdentity")
            .field("language", &self.language)
            .field("adapter", &self.adapter)
            .field("adapter_version", &self.adapter_version)
            .field("runtime_version", &self.runtime_version)
            .finish()
    }
}

/// Optional confidence score in `[0.0, 1.0]`. `None` means the
/// producer did not declare a confidence value.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Confidence(f32);

impl Confidence {
    /// Wraps a normalized confidence value. Returns `None` for values
    /// outside `[0.0, 1.0]` so callers cannot smuggle unconstrained
    /// floats into reconciliation logic.
    #[must_use]
    pub fn new(value: f32) -> Option<Self> {
        if (0.0..=1.0).contains(&value) && value.is_finite() { Some(Self(value)) } else { None }
    }

    /// Returns the raw value.
    #[must_use]
    pub const fn value(self) -> f32 {
        self.0
    }
}

impl fmt::Debug for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Confidence({:.3})", self.0)
    }
}

/// A `1`-based line offset and inclusive byte range within a source
/// artifact. Both fields are optional so a partial range remains a
/// usable evidence reference.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceRange {
    /// Logical source line (`1`-based).
    pub start_line: Option<u32>,
    /// Logical source column (`1`-based).
    pub start_column: Option<u32>,
    /// Inclusive logical source line end.
    pub end_line: Option<u32>,
    /// Inclusive logical source column end.
    pub end_column: Option<u32>,
    /// Repository-relative UTF-8 path. The path is never absolute and
    /// never carries a leading platform separator.
    pub path: String,
    /// BLAKE3 identity of the exact source bytes attested at compile time.
    pub content_hash: Option<ContentHash>,
}

/// Runtime outcome when binding a method frame to source metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceBinding {
    /// No source binding state was supplied for this event.
    Unspecified,
    /// The adapter reports that the exact loaded class bytes matched its build attestation.
    Verified,
    /// No compile-time source attestation entry exists.
    AttestationMissing,
    /// Loaded class bytes differ from the compile-time attestation.
    ClassBytesMismatch,
    /// The class has no usable method line table.
    DebugMetadataAbsent,
    /// The source path or range in the build attestation is invalid.
    SourceMetadataInvalid,
    /// The source file was read when the class loaded; no build attestation vouches for it.
    ObservedUnattested,
    /// A generated file was observed and no source map was found.
    SourceMapAbsent,
    /// A source map exists but the position could not be resolved through it.
    SourceMapUnresolved,
}

impl SourceBinding {
    /// Returns `true` only when the event carries compile-attested source.
    #[must_use]
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }

    /// Returns `true` when an event with this binding may carry a source range.
    #[must_use]
    pub const fn has_source_claim(self) -> bool {
        matches!(
            self,
            Self::Verified
                | Self::ObservedUnattested
                | Self::SourceMapAbsent
                | Self::SourceMapUnresolved
        )
    }

    /// Returns the snake_case wire and JSON string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Verified => "verified",
            Self::AttestationMissing => "attestation_missing",
            Self::ClassBytesMismatch => "class_bytes_mismatch",
            Self::DebugMetadataAbsent => "debug_metadata_absent",
            Self::SourceMetadataInvalid => "source_metadata_invalid",
            Self::ObservedUnattested => "observed_unattested",
            Self::SourceMapAbsent => "source_map_absent",
            Self::SourceMapUnresolved => "source_map_unresolved",
        }
    }
}

/// Longest accepted repository-relative path, in bytes.
pub const MAX_REPO_RELATIVE_PATH_BYTES: usize = 1024;

/// Returns `true` when `path` is a safe repository-relative source path.
///
/// One function serves ingest and the read projection. A safe path is 1 to 1024 bytes with no
/// leading `/`, no backslash, no NUL or other control character, no empty segment, no `.` or `..`
/// segment and no drive prefix such as `C:`. It does not check that the file exists.
#[must_use]
pub fn is_safe_repo_relative_path(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_REPO_RELATIVE_PATH_BYTES {
        return false;
    }
    if path.starts_with('/') || path.contains('\\') || path.chars().any(char::is_control) {
        return false;
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return false;
    }
    path.split('/').all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// Reference describing how an evidence item was produced.
///
/// `EvidenceRef` is immutable: a downstream layer may evolve it into
/// view-model fields, but the on-disk representation preserves every
/// component so future audits can replay the chain of custody.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// Coarse provenance classification.
    pub provenance: ProvenanceKind,
    /// Producer identity. `None` only for user-declared claims.
    pub producer: Option<ProducerIdentity>,
    /// Source revision that was current when the evidence was produced.
    pub source_revision: Option<SourceRevisionId>,
    /// Runtime session that contributed the evidence, if any.
    pub runtime_session: Option<RuntimeSessionId>,
    /// Recording that contributed the evidence, if any.
    ///
    /// The presence of a recording ID is the authoritative proof that
    /// the evidence was observed rather than inferred. UI surfaces and
    /// downstream exports must reject any frame, interaction, or value
    /// whose provenance is `Observed` but lacks a recording ID.
    pub recording: Option<RecordingId>,
    /// Source range, when the evidence points to a code location.
    pub source: Option<SourceRange>,
    /// Optional confidence score.
    pub confidence: Option<Confidence>,
    /// Stable code describing why the evidence is partial or limited.
    pub reason_code: Option<LimitationCode>,
}

impl EvidenceRef {
    /// Returns `true` if the evidence can support replay frames.
    #[must_use]
    pub const fn supports_replay(&self) -> bool {
        self.provenance.is_recording_backed() && self.recording.is_some()
    }
}

impl fmt::Debug for EvidenceRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EvidenceRef")
            .field("provenance", &self.provenance)
            .field("producer", &self.producer)
            .field("source_revision", &self.source_revision)
            .field("runtime_session", &self.runtime_session)
            .field("recording", &self.recording)
            .field("confidence", &self.confidence)
            .field("reason_code", &self.reason_code)
            .finish()
    }
}

/// Stable limitation codes used in evidence and recorded gaps.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitationCode {
    /// LocalVariableTable absent in compiled bytecode.
    NoLocalVariableTable,
    /// Source map is missing or invalid.
    MissingSourceMap,
    /// Capability not negotiated with the adapter.
    CapabilityUnsupported,
    /// Adapter dropped optional detail under backpressure.
    BackpressureDropped,
    /// Daemon shed a lower-priority event.
    DaemonShed,
    /// Capture session ended before the boundary completed.
    SessionEndedEarly,
    /// Handler identity could not be resolved.
    HandlerUnresolved,
    /// Source file does not match the recorded content hash.
    SourceHashMismatch,
}

impl LimitationCode {
    /// Returns the wire string form.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoLocalVariableTable => "no_local_variable_table",
            Self::MissingSourceMap => "missing_source_map",
            Self::CapabilityUnsupported => "capability_unsupported",
            Self::BackpressureDropped => "backpressure_dropped",
            Self::DaemonShed => "daemon_shed",
            Self::SessionEndedEarly => "session_ended_early",
            Self::HandlerUnresolved => "handler_unresolved",
            Self::SourceHashMismatch => "source_hash_mismatch",
        }
    }
}

impl fmt::Display for LimitationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_repo_relative_path_table() {
        for good in [
            "a",
            "src/main/java/app/OwnerController.java",
            "pkg/sub/file.ts",
            "dir with space/f.js",
            "..hidden/file",
            "a..b/c",
            ".github/workflows/x.yml",
            "src/\u{e9}.java",
        ] {
            assert!(is_safe_repo_relative_path(good), "{good:?} should be safe");
        }
        for bad in [
            "",
            "/etc/passwd",
            "\\\\server\\share",
            "a\\b",
            "../x",
            "a/../x",
            "a/./b",
            "./a",
            "a//b",
            "a/",
            "a/..",
            "C:/x",
            "c:x",
            "a\0b",
            "a\nb",
            "a\u{7f}b",
        ] {
            assert!(!is_safe_repo_relative_path(bad), "{bad:?} should be rejected");
        }
        assert!(is_safe_repo_relative_path(&"a".repeat(1024)));
        assert!(!is_safe_repo_relative_path(&"a".repeat(1025)));
    }

    #[test]
    fn source_binding_claims_and_strings() {
        use SourceBinding::{
            AttestationMissing, ClassBytesMismatch, DebugMetadataAbsent, ObservedUnattested,
            SourceMapAbsent, SourceMapUnresolved, SourceMetadataInvalid, Unspecified, Verified,
        };
        for b in [Verified, ObservedUnattested, SourceMapAbsent, SourceMapUnresolved] {
            assert!(b.has_source_claim(), "{b:?}");
        }
        for b in [
            Unspecified,
            AttestationMissing,
            ClassBytesMismatch,
            DebugMetadataAbsent,
            SourceMetadataInvalid,
        ] {
            assert!(!b.has_source_claim(), "{b:?}");
        }
        assert!(Verified.is_verified());
        assert!(!ObservedUnattested.is_verified(), "only Verified is attested");
        for b in [
            Unspecified,
            Verified,
            AttestationMissing,
            ClassBytesMismatch,
            DebugMetadataAbsent,
            SourceMetadataInvalid,
            ObservedUnattested,
            SourceMapAbsent,
            SourceMapUnresolved,
        ] {
            assert_eq!(serde_json::to_string(&b).unwrap(), format!("\"{}\"", b.as_str()));
        }
    }

    #[test]
    fn confidence_rejects_out_of_range() {
        assert!(Confidence::new(-0.1).is_none());
        assert!(Confidence::new(1.1).is_none());
        assert!(Confidence::new(f32::NAN).is_none());
        assert!(Confidence::new(0.5).is_some());
    }

    #[test]
    fn provenance_recording_backed_is_strict() {
        assert!(!ProvenanceKind::StaticInferred.is_recording_backed());
        assert!(!ProvenanceKind::RuntimeDiscovered.is_recording_backed());
        assert!(ProvenanceKind::Observed.is_recording_backed());
        assert!(ProvenanceKind::PartialObservation.is_recording_backed());
    }

    #[test]
    fn evidence_replay_requires_recording_id() {
        let mut evidence = EvidenceRef {
            provenance: ProvenanceKind::Observed,
            producer: None,
            source_revision: None,
            runtime_session: None,
            recording: None,
            source: None,
            confidence: None,
            reason_code: None,
        };
        assert!(!evidence.supports_replay());

        evidence.recording = Some(RecordingId::new());
        assert!(evidence.supports_replay());
    }
}
