//! Plain request and input structs. No database, no I/O, no domain handles.

use std::fmt;

/// Output format selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportFormat {
    /// OpenAPI 3.1 (JSON or YAML).
    OpenApi,
    /// Postman collection v2.1.
    Postman,
    /// POSIX `sh` cURL recipes.
    Curl,
    /// Deterministic archive bundle.
    Bundle,
}

impl ExportFormat {
    /// Stable lowercase name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::OpenApi => "openapi",
            Self::Postman => "postman",
            Self::Curl => "curl",
            Self::Bundle => "bundle",
        }
    }

    /// Parses a stable name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "openapi" => Some(Self::OpenApi),
            "postman" => Some(Self::Postman),
            "curl" => Some(Self::Curl),
            "bundle" => Some(Self::Bundle),
            _ => None,
        }
    }
}

/// What to export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportRequest {
    /// Output format.
    pub format: ExportFormat,
    /// Restrict to these operation ids (`None` = all).
    pub operation_ids: Option<Vec<String>>,
    /// Emit YAML instead of JSON where the format has both.
    pub yaml: bool,
}

impl ExportRequest {
    /// A request for every operation in the given format, JSON where relevant.
    #[must_use]
    pub fn new(format: ExportFormat) -> Self {
        Self { format, operation_ids: None, yaml: false }
    }
}

/// Catalog revision identity carried into the export.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevisionInput {
    /// Revision id.
    pub revision_id: String,
    /// Revision ordinal.
    pub ordinal: u32,
    /// Hex digest of the catalog content.
    pub catalog_hash: String,
    /// Hex digest of the policy applied.
    pub policy_digest: String,
    /// Application display name.
    pub application_name: String,
}

/// Effective state of an operation, mirroring the catalog read model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectiveState {
    /// Seen only by static analysis.
    StaticOnly,
    /// Registered by an adapter.
    Registered,
    /// Observed at runtime.
    Observed,
    /// Sources disagree.
    Conflicted,
    /// Unknown.
    Unknown,
}

impl EffectiveState {
    /// Stable snake_case name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::StaticOnly => "static_only",
            Self::Registered => "registered",
            Self::Observed => "observed",
            Self::Conflicted => "conflicted",
            Self::Unknown => "unknown",
        }
    }
}

/// One parameter claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParamInput {
    /// Parameter name.
    pub name: String,
    /// `path`, `query`, `header` or `cookie`.
    pub location: String,
    /// Declared type name (`string`, `integer`, ...); empty = unknown.
    pub type_name: String,
    /// Declared required.
    pub required: bool,
    /// Where the claim came from.
    pub source: String,
}

/// One response claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseInput {
    /// Status code text (`200`, `4XX`, `default`).
    pub status: String,
    /// Description; may be empty.
    pub description: String,
}

/// Where an example value came from. There is no `Observed` origin: X-trace
/// never retains observed bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExampleOrigin {
    /// A scenario file.
    Scenario,
    /// A catalog claim.
    Claim,
    /// Inferred by the exporter from a type.
    Inferred,
}

impl ExampleOrigin {
    /// Stable name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Scenario => "scenario",
            Self::Claim => "claim",
            Self::Inferred => "inferred",
        }
    }
}

/// An example value (JSON text for bodies, plain text otherwise).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExampleInput {
    /// Label (for example `create-order`).
    pub label: String,
    /// What the example is attached to: `request_body`, or a parameter name
    /// prefixed `param:`.
    pub target: String,
    /// Origin.
    pub origin: ExampleOrigin,
    /// The value text.
    pub value: String,
}

/// Handler reference (no source excerpt).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandlerInput {
    /// Symbol.
    pub symbol: String,
    /// Repo-relative path.
    pub path: String,
    /// First line.
    pub line_start: u32,
    /// Last line.
    pub line_end: u32,
}

/// One claim about an operation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClaimInput {
    /// Claim id.
    pub claim_id: String,
    /// Provenance label.
    pub provenance: String,
    /// Confidence in basis points.
    pub confidence_basis_points: Option<u16>,
    /// Limitation codes.
    pub limitation_codes: Vec<String>,
    /// Parameters.
    pub params: Vec<ParamInput>,
    /// Responses.
    pub responses: Vec<ResponseInput>,
    /// Examples.
    pub examples: Vec<ExampleInput>,
    /// Handler.
    pub handler: Option<HandlerInput>,
    /// Request body media type, when the claim declares a body.
    pub request_body_media_type: Option<String>,
}

/// One catalog operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationInput {
    /// Operation id.
    pub operation_id: String,
    /// HTTP method.
    pub method: String,
    /// Route template.
    pub route_template: String,
    /// Application component.
    pub application_component: String,
    /// Binding key.
    pub binding_key: String,
    /// Effective state.
    pub effective_state: EffectiveState,
    /// False when the claims projection was unavailable (claims is then empty).
    pub claims_available: bool,
    /// Claims.
    pub claims: Vec<ClaimInput>,
}

/// Everything an export reads. Built by an adapter over the catalog read port.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExportInput {
    /// Revision identity.
    pub revision: RevisionInput,
    /// Operations in any order.
    pub operations: Vec<OperationInput>,
    /// True when the read port truncated the view.
    pub truncated: bool,
}

/// Something deliberately left out of an export.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Omission {
    /// Operation id, or empty for export-wide omissions.
    pub operation_id: String,
    /// What was left out (`example`, `claims`, `truncated_view`, ...).
    pub what: String,
    /// Machine-readable reason.
    pub reason: String,
}

/// One produced file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportFile {
    /// Relative path using `/`.
    pub path: String,
    /// Unix mode to create it with (never executable).
    pub mode: u32,
    /// Content.
    pub bytes: Vec<u8>,
}

/// Result of an export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportOutput {
    /// Files, sorted by path.
    pub files: Vec<ExportFile>,
    /// Omissions, sorted.
    pub omissions: Vec<Omission>,
    /// Hex BLAKE3 over the length-prefixed (path, mode, bytes) of every file.
    pub content_hash: String,
}

/// Export failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExportError {
    /// The format exists in the CLI vocabulary but is not built yet.
    FormatNotImplemented {
        /// Format name.
        format: &'static str,
    },
    /// The finished document contained a secret-shaped value; nothing is emitted.
    SecretShaped {
        /// JSON pointer-like path to the offender (value is never included).
        path: String,
    },
    /// The generated document failed its own structural validation.
    InvalidDocument {
        /// Problems found.
        problems: Vec<String>,
    },
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FormatNotImplemented { format } => {
                write!(f, "export format {format} is not implemented in this build")
            }
            Self::SecretShaped { path } => {
                write!(f, "refusing to emit a secret-shaped value at {path}")
            }
            Self::InvalidDocument { problems } => {
                write!(f, "generated document is invalid: {}", problems.join("; "))
            }
        }
    }
}

impl std::error::Error for ExportError {}
