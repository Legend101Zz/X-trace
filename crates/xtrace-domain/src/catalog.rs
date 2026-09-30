//! Catalog aggregate.
//!
//! The catalog is the source of truth for HTTP operations, their
//! reconciled versions, and the contributing endpoint claims. Slice 1A
//! keeps the surface small: enough to store and read operations
//! reconciled by a future runtime adapter.

use serde::{Deserialize, Serialize};

use crate::ids::{ClaimId, OperationId, OperationVersionId, ProjectId};
use crate::provenance::{EvidenceRef, ProducerIdentity, ProvenanceKind, SourceRange};

/// Transport binding. Slice 1A only models HTTP because the X-trace
/// v1 framework matrix is HTTP-centric.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Plain HTTP / HTTPS.
    Http,
}

impl Transport {
    /// Returns the wire string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
        }
    }
}

/// Normalized HTTP method. Stored uppercase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP HEAD.
    Head,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP PATCH.
    Patch,
    /// HTTP DELETE.
    Delete,
    /// HTTP OPTIONS.
    Options,
    /// HTTP TRACE.
    Trace,
    /// HTTP CONNECT.
    Connect,
}

impl HttpMethod {
    /// Returns the canonical uppercase form used for identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
        }
    }

    /// Parses an HTTP method. Returns `None` for unknown verbs.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "GET" => Some(Self::Get),
            "HEAD" => Some(Self::Head),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "PATCH" => Some(Self::Patch),
            "DELETE" => Some(Self::Delete),
            "OPTIONS" => Some(Self::Options),
            "TRACE" => Some(Self::Trace),
            "CONNECT" => Some(Self::Connect),
            _ => None,
        }
    }
}

/// Stable HTTP operation identity.
///
/// `OperationId` is the durable, framework-neutral identifier X-trace
/// uses to recognize an endpoint across handler refactors. It is the
/// foreign key the recordings, exercise plans, and exports hang off.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Operation {
    /// UUIDv7 entity identifier allocated on first persistence; endpoint
    /// matching uses a separate versioned fingerprint.
    pub id: OperationId,
    /// Owning project.
    pub project_id: ProjectId,
    /// Transport binding.
    pub transport: Transport,
    /// HTTP method.
    pub method: HttpMethod,
    /// Normalized route shape (e.g. `/orders/{id}`).
    pub normalized_route_shape: String,
    /// Application component (e.g. `order-service`). Used to disambiguate
    /// routes that share a shape across services.
    pub application_component: String,
    /// Virtual-host / base-path identity (e.g. `default`).
    pub binding_key: String,
    /// Display route preferred by the highest-confidence current
    /// claim. Falls back to `normalized_route_shape` when no claim has
    /// claimed a display template.
    pub display_route: String,
}

impl Operation {
    /// Returns the stable operation identifier.
    #[must_use]
    pub const fn id(&self) -> OperationId {
        self.id
    }
}

/// Reconciled operation version.
///
/// `OperationVersionId` hashes the operation ID plus the reconciled
/// signature, claim set, schemas, security, provenance, and lifecycle.
/// Slice 1A models the lifecycle as a small enum so future slices can
/// extend it without breaking the wire format.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationVersion {
    /// Stable identifier of the version.
    pub id: OperationVersionId,
    /// Owning operation.
    pub operation_id: OperationId,
    /// Lifecycle state observed for this version.
    pub lifecycle: OperationLifecycle,
    /// Deterministic digest over the reconciled signature.
    pub digest: String,
}

/// Lifecycle observed for a reconciled operation version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationLifecycle {
    /// Only inferred or imported claims contributed.
    Inferred,
    /// A live framework registered the handler but no execution occurred.
    Registered,
    /// At least one observed recording exists for the version.
    Observed,
    /// The version was removed in a later catalog revision.
    Removed,
}

impl OperationLifecycle {
    /// Returns the wire string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inferred => "inferred",
            Self::Registered => "registered",
            Self::Observed => "observed",
            Self::Removed => "removed",
        }
    }
}

/// Claim contributed by a producer about an operation.
///
/// Claims are immutable; reconciliation produces a new
/// [`OperationVersion`] rather than mutating an existing claim.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct EndpointClaim {
    /// Stable identifier of the claim.
    pub id: ClaimId,
    /// Operation the claim is about.
    pub operation_id: OperationId,
    /// Optional producer manifest that emitted the claim. `None` for
    /// user-declared claims.
    pub producer: Option<ProducerIdentity>,
    /// Provenance classification of the claim.
    pub provenance: ProvenanceKind,
    /// Optional source ranges pointing at the handler or interceptor.
    pub source_ranges: Vec<SourceRange>,
    /// Evidence summary for the claim.
    pub evidence: EvidenceRef,
    /// Capture eligibility reasoning. `None` when the policy has not
    /// been evaluated yet.
    pub capture_eligibility_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_method_round_trips_canonical_form() {
        for verb in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
            let parsed = HttpMethod::parse(verb).unwrap();
            assert_eq!(parsed.as_str(), verb);
        }
        assert!(HttpMethod::parse("BREW").is_none());
        // Lowercase input must normalize to uppercase.
        assert_eq!(HttpMethod::parse("post").unwrap().as_str(), "POST");
    }
}
