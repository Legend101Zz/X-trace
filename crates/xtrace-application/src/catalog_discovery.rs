//! Application boundary for durable, owner-scoped catalog discovery.
//!
//! Producer-supplied scopes, manifests, claims, and transcript digests are
//! declarations. This module requires an opaque owner-policy result before
//! it calls any write port. The shipped admission implementation refuses
//! until the runtime has a verified pack, persisted owner selection, and
//! immutable source-snapshot authority.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use xtrace_domain::catalog_discovery::{
    ClaimSourceEvidence, DiscoveryChunk, DiscoveryProofError, DiscoveryRefusal, DiscoveryRunFinish,
    DiscoveryRunGrant, DiscoveryRunStartRequest, DiscoveryScope,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    AppError, ContentHash, CorrelationId, ErrorCategory, ErrorCode, OperationId, ProjectId,
    RetryAdvice, RunId, RuntimeSessionId, SourceRevisionId,
};

use crate::error::PortError;

pub mod admission;
pub mod history;

/// Authenticated transport context supplied by the runtime session manager.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogProducerContext {
    /// Project authenticated by the daemon session.
    pub project_id: ProjectId,
    /// Runtime session authenticated by the daemon session.
    pub runtime_session_id: RuntimeSessionId,
    /// Independently verified pack digest; producer Hello text is not enough.
    pub verified_pack_digest: ContentHash,
    /// Negotiated protocol minor version.
    pub protocol_minor: u32,
    /// Whether the daemon negotiated the scoped catalog capability.
    pub scoped_discovery_negotiated: bool,
    /// Trusted origin namespace for retry identity. Local static scans and
    /// adapter requests must never alias the same producer hint.
    pub namespace: CatalogRunNamespace,
}

/// Distinct idempotency namespaces for local scans and runtime producers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogRunNamespace {
    /// A user-requested local static scanner run.
    LocalStaticScanner,
    /// A discovery request from an authenticated runtime adapter.
    RuntimeProducer,
}

impl CatalogRunNamespace {
    /// Stable value used only for durable retry identity.
    #[must_use]
    pub const fn storage_key(self) -> &'static str {
        match self {
            Self::LocalStaticScanner => "local_static_scanner",
            Self::RuntimeProducer => "runtime_producer",
        }
    }
}

/// Opaque result of owner selection and pack/scope admission.
///
/// Fields are intentionally private. Only code inside this application crate
/// can create this value; an inbound DTO or downstream port cannot mint
/// catalog authority by constructing a boolean or copying producer claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedCatalogSelection {
    project_id: ProjectId,
    runtime_session_id: RuntimeSessionId,
    verified_pack_digest: ContentHash,
    protocol_minor: u32,
    namespace: CatalogRunNamespace,
    owner_selection_id: [u8; 16],
    owner_selection_epoch: u64,
    scope: DiscoveryScope,
    source_revision_id: Option<SourceRevisionId>,
    pinned_source_digest: Option<ContentHash>,
}

impl AdmittedCatalogSelection {
    /// Project fixed by the authenticated session and owner policy.
    #[must_use]
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Runtime identity fixed by the authenticated session.
    #[must_use]
    pub const fn runtime_session_id(&self) -> RuntimeSessionId {
        self.runtime_session_id
    }

    /// Verified pack digest resolved by trusted admission.
    #[must_use]
    pub const fn verified_pack_digest(&self) -> ContentHash {
        self.verified_pack_digest
    }

    /// Protocol minor version admitted by the trusted session capability
    /// negotiation.
    #[must_use]
    pub const fn protocol_minor(&self) -> u32 {
        self.protocol_minor
    }

    /// Retry namespace resolved by trusted admission.
    #[must_use]
    pub const fn namespace(&self) -> CatalogRunNamespace {
        self.namespace
    }

    /// Stable owner-selection row identity.
    #[must_use]
    pub const fn owner_selection_id(&self) -> &[u8; 16] {
        &self.owner_selection_id
    }

    /// Current revocation epoch read and checked in the write transaction.
    #[must_use]
    pub const fn owner_selection_epoch(&self) -> u64 {
        self.owner_selection_epoch
    }

    /// Exact immutable coverage admitted by the owner.
    #[must_use]
    pub const fn scope(&self) -> &DiscoveryScope {
        &self.scope
    }

    /// Core-resolved pinned source revision for static scans.
    #[must_use]
    pub const fn source_revision_id(&self) -> Option<SourceRevisionId> {
        self.source_revision_id
    }

    /// Digest of the exact owner-pinned source snapshot, when applicable.
    #[must_use]
    pub const fn pinned_source_digest(&self) -> Option<ContentHash> {
        self.pinned_source_digest
    }
}

/// Resolves an immutable owner selection and separately verified pack.
///
/// Implementations are part of the trusted application boundary. The
/// producer's owner-selection reference is a lookup key only; all returned
/// identities and epochs must come from trusted persisted policy.
pub trait CatalogAdmissionPort: Send + Sync {
    /// Resolves an exact Start retry against its original persisted owner
    /// selection before a fresh selection can be chosen.
    fn resolve_start_retry(
        &self,
        context: CatalogProducerContext,
        request: &DiscoveryRunStartRequest,
    ) -> Result<Option<AdmittedCatalogSelection>, DiscoveryRefusal>;

    /// Resolves a requested scope or returns a stable refusal.
    fn admit(
        &self,
        context: CatalogProducerContext,
        request: &DiscoveryRunStartRequest,
    ) -> Result<AdmittedCatalogSelection, DiscoveryRefusal>;

    /// Reloads the original persisted selection for an existing run. An
    /// implementation must not substitute the latest selection after a
    /// lost response or a newer owner choice.
    fn resolve_run(
        &self,
        context: CatalogProducerContext,
        run_id: RunId,
    ) -> Result<AdmittedCatalogSelection, DiscoveryRefusal>;
}

/// Default live admission while owner selection and P07 verification are
/// unavailable. It performs no catalog writes and allocates no public IDs.
#[derive(Clone, Copy, Debug, Default)]
pub struct RefuseCatalogAdmission;

impl CatalogAdmissionPort for RefuseCatalogAdmission {
    fn resolve_start_retry(
        &self,
        context: CatalogProducerContext,
        _request: &DiscoveryRunStartRequest,
    ) -> Result<Option<AdmittedCatalogSelection>, DiscoveryRefusal> {
        if !context.scoped_discovery_negotiated {
            return Err(DiscoveryRefusal::CapabilityNotNegotiated);
        }
        Ok(None)
    }

    fn admit(
        &self,
        context: CatalogProducerContext,
        _request: &DiscoveryRunStartRequest,
    ) -> Result<AdmittedCatalogSelection, DiscoveryRefusal> {
        if !context.scoped_discovery_negotiated {
            return Err(DiscoveryRefusal::CapabilityNotNegotiated);
        }
        Err(DiscoveryRefusal::UnverifiedManifest)
    }

    fn resolve_run(
        &self,
        context: CatalogProducerContext,
        _run_id: RunId,
    ) -> Result<AdmittedCatalogSelection, DiscoveryRefusal> {
        if !context.scoped_discovery_negotiated {
            return Err(DiscoveryRefusal::CapabilityNotNegotiated);
        }
        Err(DiscoveryRefusal::UnverifiedManifest)
    }
}

/// Independently binds source-bearing claim evidence to the admitted bytes.
pub trait CatalogSourceProofPort: Send + Sync {
    /// Verifies source evidence for a single typed claim.
    fn verify_claim(
        &self,
        selection: &AdmittedCatalogSelection,
        claim: &xtrace_domain::catalog_discovery::ValidatedEndpointClaim,
    ) -> Result<(), DiscoveryRefusal>;
}

/// Fail-closed source proof implementation for the current product runtime.
#[derive(Clone, Copy, Debug, Default)]
pub struct RefuseUnboundSourceEvidence;

impl CatalogSourceProofPort for RefuseUnboundSourceEvidence {
    fn verify_claim(
        &self,
        _selection: &AdmittedCatalogSelection,
        claim: &xtrace_domain::catalog_discovery::ValidatedEndpointClaim,
    ) -> Result<(), DiscoveryRefusal> {
        if claim.source_evidence().iter().any(|evidence| {
            matches!(
                evidence,
                ClaimSourceEvidence::StaticSnapshot { .. }
                    | ClaimSourceEvidence::LoadedClassBound { .. }
            )
        }) {
            return Err(DiscoveryRefusal::SourceSnapshotUnavailable);
        }
        Ok(())
    }
}

/// Durable transaction boundary implemented by the store crate.
pub trait CatalogDiscoveryWritePort: Send + Sync {
    /// Persists or exactly replays an admitted Start and returns its core ID.
    fn start_run(
        &self,
        selection: &AdmittedCatalogSelection,
        request: &DiscoveryRunStartRequest,
    ) -> Result<DiscoveryRunGrant, PortError>;

    /// Atomically persists one bounded chunk or returns its exact replay.
    fn submit_chunk(
        &self,
        selection: &AdmittedCatalogSelection,
        chunk: &DiscoveryChunk,
    ) -> Result<(), PortError>;

    /// Reconciles and commits a terminal result after rechecking authority.
    fn finish_run(
        &self,
        selection: &AdmittedCatalogSelection,
        finish: &DiscoveryRunFinish,
    ) -> Result<(), PortError>;
}

/// Durable catalog command service.
pub struct CatalogDiscoveryService {
    admission: Arc<dyn CatalogAdmissionPort>,
    source_proof: Arc<dyn CatalogSourceProofPort>,
    writer: Arc<dyn CatalogDiscoveryWritePort>,
}

impl CatalogDiscoveryService {
    /// Constructs the live service with fail-closed admission and source
    /// verification. A production caller cannot inject producer-derived
    /// selection state through this constructor.
    #[must_use]
    pub fn new(writer: Arc<dyn CatalogDiscoveryWritePort>) -> Self {
        Self {
            admission: Arc::new(RefuseCatalogAdmission),
            source_proof: Arc::new(RefuseUnboundSourceEvidence),
            writer,
        }
    }

    /// Admits and durably records a Start. Refusal occurs before the writer
    /// is called, so rejected starts allocate no public identifier.
    pub fn start_run(
        &self,
        context: CatalogProducerContext,
        request: &DiscoveryRunStartRequest,
    ) -> Result<DiscoveryRunGrant, CatalogDiscoveryError> {
        request.validate()?;
        let selection = match self
            .admission
            .resolve_start_retry(context, request)
            .map_err(CatalogDiscoveryError::Refused)?
        {
            Some(selection) => selection,
            None => {
                self.admission.admit(context, request).map_err(CatalogDiscoveryError::Refused)?
            }
        };
        if !selection_matches_context(&selection, context)
            || selection.scope.canonical_bytes()? != request.requested_scope.canonical_bytes()?
        {
            return Err(CatalogDiscoveryError::Refused(DiscoveryRefusal::ScopeNotAuthorized));
        }
        self.writer.start_run(&selection, request).map_err(CatalogDiscoveryError::Port)
    }

    /// Checks source claims and persists a bounded chunk in one store
    /// transaction. Static and loaded-class evidence remains unavailable
    /// until an independent byte/manifest proof implementation exists.
    pub fn submit_chunk(
        &self,
        context: CatalogProducerContext,
        chunk: &DiscoveryChunk,
    ) -> Result<(), CatalogDiscoveryError> {
        let selection = self
            .admission
            .resolve_run(context, chunk.run_id)
            .map_err(CatalogDiscoveryError::Refused)?;
        if !selection_matches_context(&selection, context) {
            return Err(CatalogDiscoveryError::Refused(DiscoveryRefusal::ScopeNotAuthorized));
        }
        if chunk.claims.iter().any(|claim| {
            matches!(
                claim.provenance(),
                xtrace_domain::catalog_discovery::ClaimProvenance::Observed
                    | xtrace_domain::catalog_discovery::ClaimProvenance::PartialObservation
            )
        }) {
            return Err(CatalogDiscoveryError::Refused(DiscoveryRefusal::ScopeNotAuthorized));
        }
        for claim in &chunk.claims {
            self.source_proof
                .verify_claim(&selection, claim)
                .map_err(CatalogDiscoveryError::Refused)?;
        }
        self.writer.submit_chunk(&selection, chunk).map_err(CatalogDiscoveryError::Port)
    }

    /// Verifies and durably finalizes a run.
    pub fn finish_run(
        &self,
        context: CatalogProducerContext,
        finish: &DiscoveryRunFinish,
    ) -> Result<(), CatalogDiscoveryError> {
        let selection = self
            .admission
            .resolve_run(context, finish.run_id)
            .map_err(CatalogDiscoveryError::Refused)?;
        if !selection_matches_context(&selection, context) {
            return Err(CatalogDiscoveryError::Refused(DiscoveryRefusal::ScopeNotAuthorized));
        }
        self.writer.finish_run(&selection, finish).map_err(CatalogDiscoveryError::Port)
    }

    #[cfg(test)]
    pub(crate) fn with_test_ports(
        admission: Arc<dyn CatalogAdmissionPort>,
        source_proof: Arc<dyn CatalogSourceProofPort>,
        writer: Arc<dyn CatalogDiscoveryWritePort>,
    ) -> Self {
        Self { admission, source_proof, writer }
    }
}

fn selection_matches_context(
    selection: &AdmittedCatalogSelection,
    context: CatalogProducerContext,
) -> bool {
    context.scoped_discovery_negotiated
        && selection.project_id == context.project_id
        && selection.runtime_session_id == context.runtime_session_id
        && selection.verified_pack_digest == context.verified_pack_digest
        && selection.protocol_minor == context.protocol_minor
        && selection.namespace == context.namespace
}

/// Safe application failure for catalog discovery.
#[derive(Debug, Error)]
pub enum CatalogDiscoveryError {
    /// The typed request failed its bounded canonical validator.
    #[error("catalog discovery request is invalid")]
    Invalid(#[from] DiscoveryProofError),
    /// Trusted admission or independent source proof refused the request.
    #[error("catalog discovery is unavailable: {0:?}")]
    Refused(DiscoveryRefusal),
    /// A durable store operation failed.
    #[error("catalog discovery persistence failed")]
    Port(PortError),
}

/// Read port is separate so projections can never materialize write-only
/// canonical claim bytes or private selection bindings.
pub trait CatalogReadPort: Send + Sync {
    /// Loads a bounded safe summary for a project/revision pair.
    fn read_revision_summary(
        &self,
        project_id: ProjectId,
        revision_id: xtrace_domain::CatalogRevisionId,
    ) -> Result<CatalogRevisionSummary, PortError>;

    /// Reads one capped page from one immutable project/revision pair.
    fn list_revision_operations(
        &self,
        project_id: ProjectId,
        revision_id: xtrace_domain::CatalogRevisionId,
        filter: CatalogOperationFilter,
        after: Option<OperationId>,
        limit: u32,
    ) -> Result<(Vec<CatalogOperationRecord>, bool), PortError>;
}

/// Safe revision summary; it deliberately omits canonical claim bytes,
/// absolute roots, producer hints, and owner-selection internals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogRevisionSummary {
    /// Public project identity.
    pub project_id: ProjectId,
    /// Public revision identity.
    pub revision_id: xtrace_domain::CatalogRevisionId,
    /// Stable scope identity, not raw scope text.
    pub scope_digest: ContentHash,
    /// Immutable source revision selected for a static scan, if applicable.
    pub source_revision_id: Option<SourceRevisionId>,
    /// Completion is based on persisted transcript proof.
    pub completion: xtrace_domain::catalog_discovery::DiscoveryCompletion,
    /// Number of safe operation summaries in this revision.
    pub operation_count: u32,
}

/// Filter bound into every catalog operation page cursor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CatalogOperationFilter {
    /// Optional revision change kind.
    pub change_kind: Option<CatalogChangeKind>,
}

/// Safe, closed revision change labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogChangeKind {
    /// Newly present in this revision.
    Added,
    /// Same stable operation version as the preceding revision.
    Unchanged,
    /// Same operation identity with a changed version digest.
    Changed,
    /// Absent from a complete, sufficiently authorized scope comparison.
    Removed,
    /// No safe removal conclusion is available.
    Unknown,
}

impl CatalogChangeKind {
    /// Stable SQLite and cursor label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Unchanged => "unchanged",
            Self::Changed => "changed",
            Self::Removed => "removed",
            Self::Unknown => "unknown",
        }
    }
}

/// Closed read projection for the catalog's current source-proof boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogSourceAvailability {
    /// Claim evidence is structurally valid but not independently verified.
    Unverified,
    /// No source data is available for this carried-forward row.
    Unavailable,
}

/// Safe operation summary; source paths, handler labels, and canonical claim
/// payloads are deliberately not projected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogOperationRecord {
    /// Core-issued stable operation identity.
    pub operation_id: OperationId,
    /// Distinct validated claim provenance values for this revision entry.
    pub provenance: Vec<xtrace_domain::catalog_discovery::ClaimProvenance>,
    /// Stable closed-vocabulary limitations from validated claims.
    pub limitation_codes: Vec<String>,
    /// Change classification against the preceding revision.
    pub change_kind: CatalogChangeKind,
    /// Explicit limit of current source verification.
    pub source_availability: CatalogSourceAvailability,
}

/// Project/revision/filter-bound list request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListCatalogOperations {
    /// Owning project; cursors are bound to this value.
    pub project_id: ProjectId,
    /// Immutable revision to query.
    pub revision_id: xtrace_domain::CatalogRevisionId,
    /// Filter included in cursor identity.
    pub filter: CatalogOperationFilter,
    /// Requested page size, default 50 and maximum 100.
    pub limit: Option<u32>,
    /// Opaque continuation cursor from the preceding page.
    pub cursor: Option<String>,
}

/// Bounded safe operation page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogOperationsPage {
    /// Safe endpoint projections.
    pub items: Vec<CatalogOperationRecord>,
    /// Opaque continuation token, absent at the end.
    pub next_cursor: Option<String>,
    /// Persisted terminal state for the revision represented by this page.
    pub completion: xtrace_domain::catalog_discovery::DiscoveryCompletion,
}

/// Framework-neutral revision query service with opaque bound cursors.
pub struct CatalogQueryService<P> {
    port: P,
}

impl<P: CatalogReadPort> CatalogQueryService<P> {
    /// Creates the query service over the shared typed read port.
    pub const fn new(port: P) -> Self {
        Self { port }
    }

    /// Lists operations under one project, immutable revision, and filter.
    pub fn list_operations(
        &self,
        request: ListCatalogOperations,
        correlation_id: CorrelationId,
    ) -> Result<CatalogOperationsPage, AppError> {
        let limit = request.limit.unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err(catalog_query_error(correlation_id, false));
        }
        let after = request
            .cursor
            .as_deref()
            .map(decode_catalog_cursor)
            .transpose()
            .map_err(|()| catalog_query_error(correlation_id, true))?;
        if after.as_ref().is_some_and(|cursor| {
            cursor.project_id != request.project_id
                || cursor.revision_id != request.revision_id
                || cursor.filter != request.filter
        }) {
            return Err(catalog_query_error(correlation_id, true));
        }
        let summary = self
            .port
            .read_revision_summary(request.project_id, request.revision_id)
            .map_err(|error| crate::application::port_error_to_app_error(error, correlation_id))?;
        if summary.project_id != request.project_id || summary.revision_id != request.revision_id {
            return Err(catalog_query_error(correlation_id, false));
        }
        let (items, has_more) = self
            .port
            .list_revision_operations(
                request.project_id,
                request.revision_id,
                request.filter,
                after.map(|cursor| cursor.last_operation_id),
                limit,
            )
            .map_err(|error| crate::application::port_error_to_app_error(error, correlation_id))?;
        let next_cursor = if has_more {
            items
                .last()
                .map(|item| encode_catalog_cursor(&request, item.operation_id, correlation_id))
                .transpose()?
        } else {
            None
        };
        Ok(CatalogOperationsPage { items, next_cursor, completion: summary.completion })
    }
}

const MAX_CATALOG_CURSOR_BYTES: usize = 2048;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogCursor {
    version: u32,
    project_id: String,
    revision_id: String,
    filter: CatalogOperationFilter,
    sort: String,
    last_operation_id: String,
}

struct DecodedCatalogCursor {
    project_id: ProjectId,
    revision_id: xtrace_domain::CatalogRevisionId,
    filter: CatalogOperationFilter,
    last_operation_id: OperationId,
}

fn encode_catalog_cursor(
    request: &ListCatalogOperations,
    last_operation_id: OperationId,
    correlation_id: CorrelationId,
) -> Result<String, AppError> {
    let cursor = CatalogCursor {
        version: 1,
        project_id: request.project_id.to_string(),
        revision_id: request.revision_id.to_string(),
        filter: request.filter,
        sort: "operation_id_asc".to_owned(),
        last_operation_id: last_operation_id.to_string(),
    };
    let token = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&cursor).map_err(|_| catalog_query_error(correlation_id, true))?,
    );
    if token.len() > MAX_CATALOG_CURSOR_BYTES {
        return Err(catalog_query_error(correlation_id, true));
    }
    Ok(token)
}

fn decode_catalog_cursor(token: &str) -> Result<DecodedCatalogCursor, ()> {
    if token.is_empty() || token.len() > MAX_CATALOG_CURSOR_BYTES || token.contains('=') {
        return Err(());
    }
    let bytes = URL_SAFE_NO_PAD.decode(token).map_err(|_| ())?;
    if URL_SAFE_NO_PAD.encode(&bytes) != token {
        return Err(());
    }
    let cursor: CatalogCursor = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if cursor.version != 1 || cursor.sort != "operation_id_asc" {
        return Err(());
    }
    if serde_json::to_vec(&cursor).map_err(|_| ())? != bytes {
        return Err(());
    }
    let project_id = cursor.project_id.parse::<ProjectId>().map_err(|_| ())?;
    let revision_id =
        cursor.revision_id.parse::<xtrace_domain::CatalogRevisionId>().map_err(|_| ())?;
    let last_operation_id = cursor.last_operation_id.parse::<OperationId>().map_err(|_| ())?;
    if project_id.to_string() != cursor.project_id
        || revision_id.to_string() != cursor.revision_id
        || last_operation_id.to_string() != cursor.last_operation_id
        || project_id.as_uuid().get_version_num() != 7
        || project_id.as_uuid().get_variant() != uuid::Variant::RFC4122
        || revision_id.as_uuid().get_version_num() != 7
        || revision_id.as_uuid().get_variant() != uuid::Variant::RFC4122
        || last_operation_id.as_uuid().get_version_num() != 7
        || last_operation_id.as_uuid().get_variant() != uuid::Variant::RFC4122
    {
        return Err(());
    }
    Ok(DecodedCatalogCursor { project_id, revision_id, filter: cursor.filter, last_operation_id })
}

fn catalog_query_error(correlation_id: CorrelationId, cursor: bool) -> AppError {
    let (code, message) = if cursor {
        ("XTR-VALIDATION-CATALOG-CURSOR", "catalog cursor is invalid or belongs to another query")
    } else {
        ("XTR-VALIDATION-CATALOG-QUERY", "catalog query limit is outside supported bounds")
    };
    AppError::new(
        ErrorCode::new(code),
        ErrorCategory::Validation,
        message,
        RetryAdvice::None,
        correlation_id,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::error::PortErrorKind;
    use uuid::Uuid;
    use xtrace_domain::catalog_discovery::{
        DiscoveryRunGrant, DiscoveryRunStartRequest, DiscoveryScopeKind,
    };
    use xtrace_domain::{ProjectId, RuntimeSessionId};

    #[derive(Default)]
    struct CountingWriter(AtomicUsize);

    impl CatalogDiscoveryWritePort for CountingWriter {
        fn start_run(
            &self,
            _selection: &AdmittedCatalogSelection,
            _request: &DiscoveryRunStartRequest,
        ) -> Result<DiscoveryRunGrant, PortError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(PortError::new(
                PortErrorKind::Internal,
                "test writer was unexpectedly called",
                xtrace_domain::CorrelationId::new(),
            ))
        }

        fn submit_chunk(
            &self,
            _selection: &AdmittedCatalogSelection,
            _chunk: &DiscoveryChunk,
        ) -> Result<(), PortError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(PortError::new(
                PortErrorKind::Internal,
                "test writer was unexpectedly called",
                xtrace_domain::CorrelationId::new(),
            ))
        }

        fn finish_run(
            &self,
            _selection: &AdmittedCatalogSelection,
            _finish: &DiscoveryRunFinish,
        ) -> Result<(), PortError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(PortError::new(
                PortErrorKind::Internal,
                "test writer was unexpectedly called",
                xtrace_domain::CorrelationId::new(),
            ))
        }
    }

    fn request() -> DiscoveryRunStartRequest {
        DiscoveryRunStartRequest {
            schema_version: 1,
            run_hint: "request-1".to_owned(),
            requested_scope: DiscoveryScope {
                kind: DiscoveryScopeKind::RuntimeRegistration,
                source_root_key: None,
                module_selector: "admin".to_owned(),
                application_component: "orders".to_owned(),
                binding_key: "default".to_owned(),
                framework_family: "framework".to_owned(),
                producer_family: "node".to_owned(),
                ruleset_digest: ContentHash::of_bytes(b"rules-v1"),
            },
            owner_selection_ref: Some("owner-selection-1".to_owned()),
        }
    }

    fn context(negotiated: bool) -> CatalogProducerContext {
        CatalogProducerContext {
            project_id: ProjectId::from_uuid(
                Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap(),
            ),
            runtime_session_id: RuntimeSessionId::from_uuid(
                Uuid::parse_str("018f0000-0000-7000-8000-000000000002").unwrap(),
            ),
            verified_pack_digest: ContentHash::of_bytes(b"untrusted-for-this-build"),
            protocol_minor: if negotiated { 1 } else { 0 },
            scoped_discovery_negotiated: negotiated,
            namespace: CatalogRunNamespace::RuntimeProducer,
        }
    }

    #[test]
    fn missing_scoped_capability_refuses_before_writer_or_id_allocation() {
        let writer = Arc::new(CountingWriter::default());
        let service = CatalogDiscoveryService::new(writer.clone());
        let error = service.start_run(context(false), &request()).unwrap_err();
        assert!(matches!(
            error,
            CatalogDiscoveryError::Refused(DiscoveryRefusal::CapabilityNotNegotiated)
        ));
        assert_eq!(writer.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn producer_claimed_manifest_cannot_issue_owner_selection_or_start() {
        let writer = Arc::new(CountingWriter::default());
        let service = CatalogDiscoveryService::new(writer.clone());
        let error = service.start_run(context(true), &request()).unwrap_err();
        assert!(matches!(
            error,
            CatalogDiscoveryError::Refused(DiscoveryRefusal::UnverifiedManifest)
        ));
        assert_eq!(writer.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn catalog_cursor_is_canonical_and_bound_to_revision_and_filter() {
        let request = ListCatalogOperations {
            project_id: ProjectId::from_uuid(
                Uuid::parse_str("018f0000-0000-7000-8000-000000000011").unwrap(),
            ),
            revision_id: xtrace_domain::CatalogRevisionId::from_uuid(
                Uuid::parse_str("018f0000-0000-7000-8000-000000000012").unwrap(),
            ),
            filter: CatalogOperationFilter { change_kind: Some(CatalogChangeKind::Added) },
            limit: Some(10),
            cursor: None,
        };
        let operation_id = OperationId::from_uuid(
            Uuid::parse_str("018f0000-0000-7000-8000-000000000013").unwrap(),
        );
        let token =
            encode_catalog_cursor(&request, operation_id, CorrelationId::new()).expect("cursor");
        let decoded = decode_catalog_cursor(&token).expect("decode");
        assert_eq!(decoded.project_id, request.project_id);
        assert_eq!(decoded.revision_id, request.revision_id);
        assert_eq!(decoded.filter, request.filter);
        assert_eq!(decoded.last_operation_id, operation_id);
        let changed_filter = ListCatalogOperations {
            filter: CatalogOperationFilter { change_kind: Some(CatalogChangeKind::Changed) },
            ..request
        };
        assert_ne!(decoded.filter, changed_filter.filter);
    }

    #[derive(Clone)]
    struct RetryAdmission {
        original: AdmittedCatalogSelection,
        latest: AdmittedCatalogSelection,
        resolved_starts: Arc<AtomicUsize>,
        fresh_admissions: Arc<AtomicUsize>,
    }

    impl CatalogAdmissionPort for RetryAdmission {
        fn resolve_start_retry(
            &self,
            context: CatalogProducerContext,
            request: &DiscoveryRunStartRequest,
        ) -> Result<Option<AdmittedCatalogSelection>, DiscoveryRefusal> {
            if !context.scoped_discovery_negotiated {
                return Err(DiscoveryRefusal::CapabilityNotNegotiated);
            }
            let prior_resolutions = self.resolved_starts.fetch_add(1, Ordering::SeqCst);
            if request.run_hint == "retry-me" && prior_resolutions > 0 {
                Ok(Some(self.original.clone()))
            } else {
                Ok(None)
            }
        }

        fn admit(
            &self,
            _context: CatalogProducerContext,
            _request: &DiscoveryRunStartRequest,
        ) -> Result<AdmittedCatalogSelection, DiscoveryRefusal> {
            let prior_admissions = self.fresh_admissions.fetch_add(1, Ordering::SeqCst);
            if prior_admissions == 0 { Ok(self.original.clone()) } else { Ok(self.latest.clone()) }
        }

        fn resolve_run(
            &self,
            context: CatalogProducerContext,
            _run_id: RunId,
        ) -> Result<AdmittedCatalogSelection, DiscoveryRefusal> {
            if !context.scoped_discovery_negotiated {
                return Err(DiscoveryRefusal::CapabilityNotNegotiated);
            }
            Ok(self.original.clone())
        }
    }

    /// Log of `(owner selection id, epoch)` pairs observed by the grant writer.
    type SelectionLog = Arc<Mutex<Vec<([u8; 16], u64)>>>;

    struct GrantWriter {
        run_id: RunId,
        selections: SelectionLog,
    }

    impl CatalogDiscoveryWritePort for GrantWriter {
        fn start_run(
            &self,
            selection: &AdmittedCatalogSelection,
            _request: &DiscoveryRunStartRequest,
        ) -> Result<DiscoveryRunGrant, PortError> {
            self.selections
                .lock()
                .expect("record selected owner")
                .push((*selection.owner_selection_id(), selection.owner_selection_epoch()));
            Ok(DiscoveryRunGrant::Admitted {
                run_id: self.run_id,
                scope_digest: selection.scope().digest().expect("scope digest"),
                source_revision_id: selection.source_revision_id(),
            })
        }

        fn submit_chunk(
            &self,
            _selection: &AdmittedCatalogSelection,
            _chunk: &DiscoveryChunk,
        ) -> Result<(), PortError> {
            Ok(())
        }

        fn finish_run(
            &self,
            _selection: &AdmittedCatalogSelection,
            _finish: &DiscoveryRunFinish,
        ) -> Result<(), PortError> {
            Ok(())
        }
    }

    fn admitted_selection(
        ctx: CatalogProducerContext,
        selection_id: Uuid,
        epoch: u64,
    ) -> AdmittedCatalogSelection {
        AdmittedCatalogSelection {
            project_id: ctx.project_id,
            runtime_session_id: ctx.runtime_session_id,
            verified_pack_digest: ctx.verified_pack_digest,
            protocol_minor: ctx.protocol_minor,
            namespace: ctx.namespace,
            owner_selection_id: *selection_id.as_bytes(),
            owner_selection_epoch: epoch,
            scope: request().requested_scope,
            source_revision_id: None,
            pinned_source_digest: None,
        }
    }

    #[test]
    fn start_retry_resolves_original_selection_before_fresh_owner_selection() {
        let ctx = context(true);
        let original = admitted_selection(ctx, Uuid::now_v7(), 1);
        let latest = admitted_selection(ctx, Uuid::now_v7(), 2);
        let resolved = Arc::new(AtomicUsize::new(0));
        let fresh = Arc::new(AtomicUsize::new(0));
        let selections = Arc::new(Mutex::new(Vec::new()));
        let expected_original = (*original.owner_selection_id(), original.owner_selection_epoch());
        let service = CatalogDiscoveryService::with_test_ports(
            Arc::new(RetryAdmission {
                original,
                latest,
                resolved_starts: resolved.clone(),
                fresh_admissions: fresh.clone(),
            }),
            Arc::new(RefuseUnboundSourceEvidence),
            Arc::new(GrantWriter { run_id: RunId::new(), selections: selections.clone() }),
        );
        let mut retry = request();
        retry.run_hint = "retry-me".to_owned();
        service.start_run(ctx, &retry).expect("original request");
        service.start_run(ctx, &retry).expect("exact retry");
        assert_eq!(resolved.load(Ordering::SeqCst), 2);
        assert_eq!(fresh.load(Ordering::SeqCst), 1);
        assert_eq!(
            *selections.lock().expect("read selected owners"),
            [expected_original, expected_original]
        );
    }

    fn source_claim(
        evidence: ClaimSourceEvidence,
    ) -> xtrace_domain::catalog_discovery::ValidatedEndpointClaim {
        use xtrace_domain::{EndpointIdentity, HttpMethod, Transport};
        let identity = EndpointIdentity {
            project_id: ProjectId::new(),
            application_component: "orders".to_owned(),
            transport: Transport::Http,
            binding_key: "default".to_owned(),
            method: HttpMethod::Get,
            route_template: "/a".to_owned(),
        };
        xtrace_domain::catalog_discovery::ValidatedEndpointClaim::new(
            "src-1".to_owned(),
            identity,
            xtrace_domain::catalog_discovery::ClaimProvenance::StaticInferred,
            None,
            0.9,
            Vec::new(),
            vec![evidence],
        )
        .expect("valid claim")
    }

    #[test]
    fn default_source_proof_refuses_static_and_loaded_class_evidence() {
        let ctx = context(true);
        let selection = admitted_selection(ctx, Uuid::now_v7(), 1);
        let digest = ContentHash::of_bytes(b"source");
        let static_claim = source_claim(ClaimSourceEvidence::StaticSnapshot {
            source_revision_id: xtrace_domain::SourceRevisionId::new(),
            relative_path: "a.js".to_owned(),
            recorded_source_digest: digest,
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 2,
        });
        let class_claim = source_claim(ClaimSourceEvidence::LoadedClassBound {
            loaded_class_digest: ContentHash::of_bytes(b"class"),
            relative_path: "a.js".to_owned(),
            recorded_source_digest: digest,
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 2,
        });
        for claim in [&static_claim, &class_claim] {
            assert_eq!(
                RefuseUnboundSourceEvidence.verify_claim(&selection, claim),
                Err(DiscoveryRefusal::SourceSnapshotUnavailable)
            );
        }
    }

    struct SummaryReader {
        summary: CatalogRevisionSummary,
    }

    impl CatalogReadPort for SummaryReader {
        fn read_revision_summary(
            &self,
            _project_id: ProjectId,
            _revision_id: xtrace_domain::CatalogRevisionId,
        ) -> Result<CatalogRevisionSummary, PortError> {
            Ok(self.summary.clone())
        }

        fn list_revision_operations(
            &self,
            _project_id: ProjectId,
            _revision_id: xtrace_domain::CatalogRevisionId,
            _filter: CatalogOperationFilter,
            _after: Option<OperationId>,
            _limit: u32,
        ) -> Result<(Vec<CatalogOperationRecord>, bool), PortError> {
            Ok((Vec::new(), false))
        }
    }

    #[test]
    fn operation_page_completion_comes_from_the_persisted_revision_summary() {
        let project_id = ProjectId::new();
        let revision_id = xtrace_domain::CatalogRevisionId::new();
        let completion = xtrace_domain::catalog_discovery::DiscoveryCompletion::Incomplete;
        let service = CatalogQueryService::new(SummaryReader {
            summary: CatalogRevisionSummary {
                project_id,
                revision_id,
                scope_digest: ContentHash::of_bytes(b"summary-scope"),
                source_revision_id: None,
                completion,
                operation_count: 0,
            },
        });
        let page = service
            .list_operations(
                ListCatalogOperations {
                    project_id,
                    revision_id,
                    filter: CatalogOperationFilter::default(),
                    limit: Some(10),
                    cursor: None,
                },
                CorrelationId::new(),
            )
            .expect("query page");
        assert_eq!(page.completion, completion);
    }
}
