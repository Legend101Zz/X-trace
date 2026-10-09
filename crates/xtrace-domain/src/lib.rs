//! X-trace domain types.
//!
//! The domain is language-neutral, framework-neutral, and IO-free. It owns the
//! typed identifiers, provenance model, recorded-value vocabulary, and state
//! machines that every other layer must speak about.
//!
//! Slice 1A keeps the surface intentionally small: the entities required to
//! represent a project, run, catalog, recording, frame, and value snapshot
//! plus the errors that escape the domain. No code in this crate may perform
//! I/O, allocate network handles, or depend on a runtime adapter.
//!
//! ```text
//! xtrace-application -> xtrace-domain
//! xtrace-store       -> xtrace-domain
//! xtrace-protocol    -> xtrace-domain  (via thin DTO translation)
//! ```
//!
//! Anything that breaks this rule belongs in another crate.

#![allow(
    clippy::module_name_repetitions,
    reason = "domain modules are intentionally named after their entities"
)]
// Unwrap and expect are forbidden in non-test code so domain errors
// remain typed. Tests deliberately exercise fallible operations on
// fixture data and remain free to use them, hence the test-side allow.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, reason = "library code must not panic")
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on fallible fixture data"
    )
)]

pub mod catalog;
pub mod catalog_admission;
pub mod catalog_discovery;
pub mod catalog_history;
pub mod catalog_reconcile;
pub mod endpoint_identity;
pub mod endpoint_normalization;
pub mod error;
pub mod hash;
pub mod ids;
pub mod observation_classifier;
pub mod project;
pub mod provenance;
pub mod recording;
pub mod run;
pub mod runtime;
pub mod time;
pub mod value;

pub use catalog::{HttpMethod, Transport};
pub use endpoint_identity::{
    ENDPOINT_FINGERPRINT_FORMAT_VERSION, EndpointFingerprint, EndpointFingerprintEncodingError,
    EndpointIdentity,
};
pub use error::{AppError, ErrorCategory, ErrorCode, Remediation, RetryAdvice, SafeScalar, codes};
pub use hash::{ContentHash, HashParseError};
pub use ids::{
    CatalogRevisionId, ClaimId, CorrelationId, FrameId, InteractionId, OperationId,
    OperationVersionId, PolicyId, ProjectId, RecordingId, RunId, RuntimeSessionId,
    SourceArtifactId, SourceRevisionId,
};
pub use project::{FingerprintParseError, Project, RepositoryFingerprint};
pub use provenance::{
    EvidenceRef, LimitationCode, ProducerIdentity, ProvenanceKind, SourceBinding, SourceRange,
};
pub use run::{Run, RunKind, RunState};
pub use time::{MonotonicNs, WallTime};
pub use value::{CapturedValue, DropReason, SafePreview, UnavailableReason, ValueShape};
