//! Typed private inputs and lifecycle storage contract.

use serde::{Deserialize, Serialize};
use xtrace_domain::{CatalogRevisionId, OperationId, ProjectId, RecordingId};

/// Maximum lifetime, also bounding approval validity, in seconds.
pub const MAX_PLAN_LIFETIME_SECONDS: u64 = 900;
/// Maximum bytes in a supplied request body.
pub const MAX_REQUEST_BODY_BYTES: usize = 65_536;
/// Maximum serialized private plan document size.
pub const MAX_PLAN_DOCUMENT_BYTES: usize = 262_144;

/// Private operator input. Debug output deliberately never includes its content.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrivateText(pub String);

impl std::fmt::Debug for PrivateText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<private>")
    }
}

/// Request parameter location; arbitrary transport destinations are not inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputLocation {
    /// Route placeholder, encoded as one segment by a future executor.
    Path,
    /// Query string field.
    Query,
    /// HTTP header other than transport-control headers.
    Header,
    /// Cookie field, which requires a credential reference.
    Cookie,
}
impl InputLocation {
    /// Stable name used by the existing synthesis engine.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Header => "header",
            Self::Cookie => "cookie",
        }
    }
}

/// A value is either missing, explicitly provided, or an opaque reference.
/// Empty struct variants make Serde reject surplus fields in internally tagged input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum InputValue {
    /// Not observed or supplied. Declared missing values block approval.
    Unresolved {},
    /// Explicit private input. No observed example is invented.
    Operator {
        /// Private bytes; never included in a status summary.
        value: PrivateText,
    },
    /// Opaque credential-store handle; never an environment value or credential.
    CredentialReference {
        /// Identifier only; a future approved executor resolves it just in time.
        reference: PrivateText,
    },
}

/// One explicit input, with provenance retained in the immutable hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExerciseInput {
    /// Parameter name.
    pub name: String,
    /// Parameter location.
    pub location: InputLocation,
    /// Operator-declared requirement; every declared unresolved value blocks approval.
    pub required: bool,
    /// Value and source.
    pub value: InputValue,
}

/// Request body provenance. A recording alone does not prove an absent body.
/// Empty struct variants keep contradictory operator content from being ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExerciseBody {
    /// No request body is available from the recording. Blocks approval.
    NotRecorded {},
    /// Operator explicitly chose to send no body.
    EmptyByOperator {},
    /// Operator supplied bounded noncredential body bytes.
    Operator {
        /// Explicit media type (JSON or plain text in this slice).
        content_type: String,
        /// Private UTF-8 content.
        content: PrivateText,
    },
}

/// Ordinary local development ownership assertion, never inferred from loopback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentTarget {
    /// Plain loopback HTTP origin with an explicit nonzero port.
    pub base_url: String,
    /// Operator confirms the application is theirs and is a development target.
    pub operator_owned_development: bool,
}

/// Hard execution ceilings pinned in the plan; no sender is implemented here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBounds {
    /// Maximum concurrent requests.
    pub concurrency: u8,
    /// Maximum request starts per second.
    pub requests_per_second: u8,
    /// Maximum seconds per request.
    pub timeout_seconds: u8,
    /// Maximum duration for the entire one-item plan.
    pub total_seconds: u8,
    /// Maximum encoded request bytes, including headers and body.
    pub request_bytes: u32,
    /// Maximum accepted response bytes.
    pub response_bytes: u32,
    /// Redirects are forbidden in this slice.
    pub redirects: u8,
}
impl Default for ExecutionBounds {
    fn default() -> Self {
        Self {
            concurrency: 1,
            requests_per_second: 1,
            timeout_seconds: 10,
            total_seconds: 10,
            request_bytes: 131_072,
            response_bytes: 1_048_576,
            redirects: 0,
        }
    }
}

/// The operator chooses a catalog version for planning and a recording linked to its stable operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateExercisePlan {
    /// Pinned catalog revision.
    pub revision_id: CatalogRevisionId,
    /// Selected catalog operation.
    pub operation_id: OperationId,
    /// Exact selected catalog operation version. The recording does not establish this choice.
    pub selected_operation_version_id: String,
    /// Existing recording actually linked to the operation.
    pub recording_id: RecordingId,
    /// Operator-approved ordinary local development target.
    pub target: DevelopmentTarget,
    /// Explicit private inputs; unknown source values remain unresolved.
    pub inputs: Vec<ExerciseInput>,
    /// Explicit body provenance.
    pub body: ExerciseBody,
    /// Lifetime from creation, at most fifteen minutes.
    pub lifetime_seconds: u64,
}

/// Stable recording linkage together with a separately verified catalog selection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExerciseOperationBinding {
    /// Owning project.
    pub project_id: ProjectId,
    /// Stable operation linked to the recording.
    pub operation_id: OperationId,
    /// Actually linked observed recording.
    pub recording_id: RecordingId,
    /// Catalog projection for the operator-selected revision, independent of historical recording version.
    pub selected_catalog: SelectedCatalogOperation,
}

/// Proposed operation from the operator-selected immutable catalog revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedCatalogOperation {
    /// Revision selected for the new plan.
    pub revision_id: CatalogRevisionId,
    /// Digest of the pinned catalog projection.
    pub catalog_hash: String,
    /// Version identity of this operation.
    pub operation_version_id: String,
    /// Application component, preserved to distinguish route collisions.
    pub application_component: String,
    /// Binding key, preserved to distinguish route collisions.
    pub binding_key: String,
    /// Method of the selected catalog operation.
    pub method: String,
    /// Route template of the selected catalog operation.
    pub route_template: String,
    /// Conflicting claims must be classified unknown.
    pub conflicted: bool,
}

/// Immutable private plan material. Editing produces a new identity, never a patch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExercisePlanContent {
    /// Codec version.
    pub schema_version: u8,
    /// Unique plan identity; identical re-created input still needs new approval.
    pub plan_id: String,
    /// Checked observed operation binding.
    pub binding: ExerciseOperationBinding,
    /// Operator input, body and target.
    pub request: CreateExercisePlan,
    /// Creation wall time in Unix seconds.
    pub created_at: u64,
    /// Exclusive expiry wall time in Unix seconds.
    pub expires_at: u64,
    /// Required future execution limits.
    pub bounds: ExecutionBounds,
}

/// Monotonic lifecycle. A consumed approval can never be restored or retried.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExercisePhase {
    /// Created, with no review or approval implied.
    Draft {},
    /// Explicitly reviewed; still sends nothing.
    Reviewed {
        /// Time of operator review.
        reviewed_at: u64,
    },
    /// Explicit consent for this immutable reviewed hash and item set.
    Approved {
        /// Original review time.
        reviewed_at: u64,
        /// Consent time.
        approved_at: u64,
        /// Explicit per-item consent (required for mutating/unknown items).
        item_ids: Vec<String>,
    },
    /// Durably reserved before a future send. Delivery is unknown, never success.
    Consumed {
        /// Reservation time.
        consumed_at: u64,
    },
}

/// Persisted private state. The port must use durable atomic compare-and-swap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredExercisePlan {
    /// Immutable reviewed content.
    pub content: ExercisePlanContent,
    /// Hash binding every immutable field and the actual synthesized plan.
    pub plan_hash: String,
    /// Compare-and-swap revision; starts at zero.
    pub revision: u64,
    /// Approval lifecycle, deliberately excluded from the immutable content hash.
    pub phase: ExercisePhase,
}

/// Stable sanitized lifecycle errors. Offending input is never interpolated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExerciseError {
    /// Invalid or excessive input, unsafe target syntax or unsupported body.
    #[error("invalid or excessive exercise input")]
    InvalidInput,
    /// Evidence does not establish the requested project/operation/recording link.
    #[error("the selected observed operation binding is unavailable")]
    BindingUnavailable,
    /// Plan identity is absent from this project.
    #[error("exercise plan not found")]
    NotFound,
    /// Private storage failed; no request is sent.
    #[error("private exercise storage is unavailable")]
    StorageUnavailable,
    /// A previous private publication left its exclusive staging slot occupied.
    #[error("exercise staging requires owner inspection before another write")]
    StagingOccupied,
    /// Stale or concurrent transition.
    #[error("exercise state changed; review the current plan")]
    Conflict,
    /// Mutated plan or mismatching reviewed hash.
    #[error("exercise plan identity does not match")]
    HashMismatch,
    /// Expired or clock moved behind creation/last transition.
    #[error("exercise plan expired or its clock is invalid")]
    Expired,
    /// Required input or explicit body decision missing.
    #[error("exercise input or request body is unresolved")]
    UnresolvedInput,
    /// Approval omitted required item consent or prior review.
    #[error("explicit review and item approval are required")]
    ApprovalRequired,
    /// Credential-like values must use opaque references.
    #[error("exercise credentials must be opaque credential references")]
    CredentialValue,
    /// One-use reservation already made; retry would risk duplicate delivery.
    #[error("exercise approval was already consumed; delivery remains unknown")]
    AlreadyConsumed,
}

/// Adapter contract shared by a CLI and a future authenticated viewer.
///
/// No method sends requests. `replace` MUST be atomic, durable, project-scoped,
/// and fail when `expected_revision` is stale. Failure after durable publication
/// is ambiguous and MUST NOT roll state back or authorize another send.
pub trait ExercisePlanPort {
    /// Verify IDs and return a durable, actually observed binding.
    fn observed_binding(
        &self,
        project: ProjectId,
        request: &CreateExercisePlan,
    ) -> Result<ExerciseOperationBinding, ExerciseError>;
    /// Insert without replacing an existing hash. Store values only owner-privately.
    /// A durable adapter checks the trusted clock at publication and before returning success.
    fn insert(&self, plan: &StoredExercisePlan) -> Result<(), ExerciseError>;
    /// Load one exact project/hash. Missing state must never infer approval.
    fn load(&self, project: ProjectId, hash: &str) -> Result<StoredExercisePlan, ExerciseError>;
    /// Compare-and-swap lifecycle state with a durable write barrier. Under the lock,
    /// check the trusted clock at publication and before acknowledging the transition.
    /// Failure after a possible rename must leave a consumed reservation consumed.
    fn replace(
        &self,
        project: ProjectId,
        hash: &str,
        expected_revision: u64,
        next: &StoredExercisePlan,
    ) -> Result<(), ExerciseError>;
}
