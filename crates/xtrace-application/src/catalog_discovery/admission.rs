//! AD-1: admission for a user-invoked local static scan.
//!
//! The owner running `xtrace scan` in a repository IS the owner selection: the invocation names
//! the exact source tree, framework and component, so the scope is the owner's own words and no
//! producer text is trusted. The selection is persisted (with a revocation epoch) through
//! [`OwnerSelectionPort`] before any claim is written, the pinned source snapshot is recorded with
//! it, and the source proof re-reads the cited files at submit time and rejects any claim whose
//! recorded digest no longer matches the bytes on disk.
//!
//! The "pack" of a local scan is the analyzer the owner pointed at: its identity is a digest of
//! its declared name, version and ruleset. It is never signed, so every revision made this way is
//! `dev_unsigned`.

use std::collections::BTreeMap;
use std::sync::Arc;

use xtrace_domain::catalog_discovery::{
    ClaimSourceEvidence, DiscoveryRefusal, DiscoveryRunStartRequest, DiscoveryScope,
    DiscoveryScopeKind, ValidatedEndpointClaim,
};
use xtrace_domain::{ContentHash, ProjectId, RunId, RuntimeSessionId, SourceRevisionId};

use super::{
    AdmittedCatalogSelection, CatalogAdmissionPort, CatalogDiscoveryService,
    CatalogDiscoveryWritePort, CatalogProducerContext, CatalogRunNamespace, CatalogSourceProofPort,
};
use crate::error::PortError;

/// Protocol minor a local scan reports; there is no wire protocol, so this is fixed.
const LOCAL_SCAN_PROTOCOL_MINOR: u32 = 1;

/// What the owner selected when invoking a local scan.
#[derive(Clone, Debug)]
pub struct LocalScanSelection {
    /// Project the scan belongs to.
    pub project_id: ProjectId,
    /// Exact coverage; must be a static-repository scope.
    pub scope: DiscoveryScope,
    /// Identity of the analyzer that will produce claims (dev-pinned, unsigned).
    pub analyzer_digest: ContentHash,
    /// Immutable snapshot identity minted for this scan.
    pub source_revision_id: SourceRevisionId,
    /// Digest of the cited source files as the scan read them.
    pub pinned_source_digest: ContentHash,
}

/// Selection row identity returned by the persistence port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordedOwnerSelection {
    /// Selection id (UUIDv7 bytes).
    pub owner_selection_id: [u8; 16],
    /// Revocation epoch of the stored row.
    pub epoch: u64,
}

/// Persists an owner selection and makes it the current one for its scope.
pub trait OwnerSelectionPort: Send + Sync {
    /// Records the selection; any earlier selection for the same project and scope stops being
    /// current in the same transaction.
    fn record_local_scan_selection(
        &self,
        selection: &LocalScanSelection,
    ) -> Result<RecordedOwnerSelection, PortError>;
}

/// Re-reads cited source files so the proof binds claims to the bytes now on disk.
pub trait SourceSnapshotReader: Send + Sync {
    /// Digest of the repository-relative file, or `None` when it is missing or unsafe.
    fn digest(&self, relative_path: &str) -> Option<ContentHash>;
}

/// The trusted authority for one local scan run.
#[derive(Clone)]
pub struct LocalScanAuthority {
    selection: AdmittedCatalogSelection,
    reader: Arc<dyn SourceSnapshotReader>,
    runtime_session_id: RuntimeSessionId,
}

impl std::fmt::Debug for LocalScanAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalScanAuthority").finish_non_exhaustive()
    }
}

impl LocalScanAuthority {
    /// Persists the owner selection and mints the admission token for this scan.
    pub fn establish(
        port: &dyn OwnerSelectionPort,
        request: &LocalScanSelection,
        reader: Arc<dyn SourceSnapshotReader>,
    ) -> Result<Self, PortError> {
        if request.scope.kind != DiscoveryScopeKind::StaticRepository {
            return Err(PortError::new(
                crate::error::PortErrorKind::Validation,
                "a local scan needs a static repository scope",
                xtrace_domain::CorrelationId::new(),
            ));
        }
        let recorded = port.record_local_scan_selection(request)?;
        let runtime_session_id = RuntimeSessionId::new();
        let selection = AdmittedCatalogSelection {
            project_id: request.project_id,
            runtime_session_id,
            verified_pack_digest: request.analyzer_digest,
            protocol_minor: LOCAL_SCAN_PROTOCOL_MINOR,
            namespace: CatalogRunNamespace::LocalStaticScanner,
            owner_selection_id: recorded.owner_selection_id,
            owner_selection_epoch: recorded.epoch,
            scope: request.scope.clone(),
            source_revision_id: Some(request.source_revision_id),
            pinned_source_digest: Some(request.pinned_source_digest),
        };
        Ok(Self { selection, reader, runtime_session_id })
    }

    /// Transport context the service checks the token against.
    #[must_use]
    pub const fn context(&self) -> CatalogProducerContext {
        CatalogProducerContext {
            project_id: self.selection.project_id,
            runtime_session_id: self.runtime_session_id,
            verified_pack_digest: self.selection.verified_pack_digest,
            protocol_minor: LOCAL_SCAN_PROTOCOL_MINOR,
            scoped_discovery_negotiated: true,
            namespace: CatalogRunNamespace::LocalStaticScanner,
        }
    }

    /// Snapshot id every claim of this scan must cite.
    #[must_use]
    pub const fn source_revision_id(&self) -> Option<SourceRevisionId> {
        self.selection.source_revision_id
    }
}

struct LocalScanAdmission {
    authority: LocalScanAuthority,
}

impl CatalogAdmissionPort for LocalScanAdmission {
    fn resolve_start_retry(
        &self,
        _context: CatalogProducerContext,
        _request: &DiscoveryRunStartRequest,
    ) -> Result<Option<AdmittedCatalogSelection>, DiscoveryRefusal> {
        // A local scan is one process and one run: there is no earlier start to replay.
        Ok(None)
    }

    fn admit(
        &self,
        _context: CatalogProducerContext,
        request: &DiscoveryRunStartRequest,
    ) -> Result<AdmittedCatalogSelection, DiscoveryRefusal> {
        // Never widen the scope the owner selected.
        let wanted = request.requested_scope.canonical_bytes();
        let owned = self.authority.selection.scope.canonical_bytes();
        match (wanted, owned) {
            (Ok(a), Ok(b)) if a == b => Ok(self.authority.selection.clone()),
            _ => Err(DiscoveryRefusal::ScopeNotAuthorized),
        }
    }

    fn resolve_run(
        &self,
        _context: CatalogProducerContext,
        _run_id: RunId,
    ) -> Result<AdmittedCatalogSelection, DiscoveryRefusal> {
        Ok(self.authority.selection.clone())
    }
}

struct SnapshotSourceProof {
    reader: Arc<dyn SourceSnapshotReader>,
}

impl CatalogSourceProofPort for SnapshotSourceProof {
    fn verify_claim(
        &self,
        selection: &AdmittedCatalogSelection,
        claim: &ValidatedEndpointClaim,
    ) -> Result<(), DiscoveryRefusal> {
        for evidence in claim.source_evidence() {
            match evidence {
                ClaimSourceEvidence::StaticSnapshot {
                    source_revision_id,
                    relative_path,
                    recorded_source_digest,
                    ..
                } => {
                    if Some(*source_revision_id) != selection.source_revision_id {
                        return Err(DiscoveryRefusal::SourceSnapshotUnavailable);
                    }
                    match self.reader.digest(relative_path) {
                        Some(now) if now == *recorded_source_digest => {}
                        _ => return Err(DiscoveryRefusal::SourceSnapshotUnavailable),
                    }
                }
                // A local static scan has no loaded classes.
                _ => return Err(DiscoveryRefusal::SourceSnapshotUnavailable),
            }
        }
        Ok(())
    }
}

impl CatalogDiscoveryService {
    /// Service for one user-invoked local static scan. Admission is the owner's own invocation
    /// (already persisted by [`LocalScanAuthority::establish`]); source proof re-reads the files.
    #[must_use]
    pub fn for_local_scan(
        writer: Arc<dyn CatalogDiscoveryWritePort>,
        authority: &LocalScanAuthority,
    ) -> Self {
        Self {
            admission: Arc::new(LocalScanAdmission { authority: authority.clone() }),
            source_proof: Arc::new(SnapshotSourceProof { reader: Arc::clone(&authority.reader) }),
            writer,
        }
    }
}

/// Digest of a source snapshot: the sorted `(path, digest)` pairs of the cited files.
#[must_use]
pub fn snapshot_digest(files: &BTreeMap<String, ContentHash>) -> ContentHash {
    let mut input = Vec::with_capacity(64 + files.len() * 96);
    input.extend_from_slice(b"xtrace.cited-source-snapshot.v1\0");
    for (path, digest) in files {
        input.extend_from_slice(path.as_bytes());
        input.push(0);
        input.extend_from_slice(digest.as_bytes());
    }
    ContentHash::of_bytes(&input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xtrace_domain::catalog_discovery::ClaimProvenance;
    use xtrace_domain::{EndpointIdentity, HttpMethod, Transport};

    struct Fixed(Option<ContentHash>);
    impl SourceSnapshotReader for Fixed {
        fn digest(&self, _relative_path: &str) -> Option<ContentHash> {
            self.0
        }
    }

    fn scope() -> DiscoveryScope {
        DiscoveryScope {
            kind: DiscoveryScopeKind::StaticRepository,
            source_root_key: Some("src-1".to_owned()),
            module_selector: "default".to_owned(),
            application_component: "app".to_owned(),
            binding_key: "default".to_owned(),
            framework_family: "express".to_owned(),
            producer_family: "local-static-scan".to_owned(),
            ruleset_digest: ContentHash::of_bytes(b"rules"),
        }
    }

    fn selection(revision: SourceRevisionId) -> AdmittedCatalogSelection {
        AdmittedCatalogSelection {
            project_id: ProjectId::new(),
            runtime_session_id: RuntimeSessionId::new(),
            verified_pack_digest: ContentHash::of_bytes(b"pack"),
            protocol_minor: 1,
            namespace: CatalogRunNamespace::LocalStaticScanner,
            owner_selection_id: [7; 16],
            owner_selection_epoch: 1,
            scope: scope(),
            source_revision_id: Some(revision),
            pinned_source_digest: Some(ContentHash::of_bytes(b"snapshot")),
        }
    }

    fn claim(revision: SourceRevisionId, digest: ContentHash) -> ValidatedEndpointClaim {
        let identity = EndpointIdentity {
            project_id: ProjectId::new(),
            application_component: "app".to_owned(),
            transport: Transport::Http,
            binding_key: "default".to_owned(),
            method: HttpMethod::Get,
            route_template: "/a".to_owned(),
        };
        ValidatedEndpointClaim::new(
            "st-1".to_owned(),
            identity,
            ClaimProvenance::StaticInferred,
            None,
            0.9,
            Vec::new(),
            vec![ClaimSourceEvidence::StaticSnapshot {
                source_revision_id: revision,
                relative_path: "a.js".to_owned(),
                recorded_source_digest: digest,
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 2,
            }],
        )
        .expect("valid claim")
    }

    #[test]
    fn source_proof_binds_claims_to_the_bytes_on_disk_now() {
        let revision = SourceRevisionId::new();
        let selected = selection(revision);
        let recorded = ContentHash::of_bytes(b"app.get('/a')");

        let same = SnapshotSourceProof { reader: Arc::new(Fixed(Some(recorded))) };
        assert_eq!(same.verify_claim(&selected, &claim(revision, recorded)), Ok(()));

        // The file changed between analysis and persistence.
        let changed = SnapshotSourceProof {
            reader: Arc::new(Fixed(Some(ContentHash::of_bytes(b"edited")))),
        };
        assert_eq!(
            changed.verify_claim(&selected, &claim(revision, recorded)),
            Err(DiscoveryRefusal::SourceSnapshotUnavailable)
        );
        // The file vanished.
        let gone = SnapshotSourceProof { reader: Arc::new(Fixed(None)) };
        assert_eq!(
            gone.verify_claim(&selected, &claim(revision, recorded)),
            Err(DiscoveryRefusal::SourceSnapshotUnavailable)
        );
        // A claim citing another snapshot is refused even when the bytes match.
        assert_eq!(
            same.verify_claim(&selected, &claim(SourceRevisionId::new(), recorded)),
            Err(DiscoveryRefusal::SourceSnapshotUnavailable)
        );
    }

    #[test]
    fn admission_never_widens_the_selected_scope() {
        let revision = SourceRevisionId::new();
        let authority = LocalScanAuthority {
            selection: selection(revision),
            reader: Arc::new(Fixed(None)),
            runtime_session_id: RuntimeSessionId::new(),
        };
        let admission = LocalScanAdmission { authority: authority.clone() };
        let context = authority.context();
        let mut request = DiscoveryRunStartRequest {
            schema_version: 1,
            run_hint: "scan-1".to_owned(),
            requested_scope: scope(),
            owner_selection_ref: None,
        };
        assert!(admission.admit(context, &request).is_ok());
        request.requested_scope.module_selector = "elsewhere".to_owned();
        assert_eq!(
            admission.admit(context, &request).unwrap_err(),
            DiscoveryRefusal::ScopeNotAuthorized
        );
    }

    #[test]
    fn snapshot_digest_depends_on_paths_and_bytes_and_not_on_insertion_order() {
        let a = ContentHash::of_bytes(b"a");
        let b = ContentHash::of_bytes(b"b");
        let mut one = BTreeMap::new();
        one.insert("x.js".to_owned(), a);
        one.insert("y.js".to_owned(), b);
        let mut two = BTreeMap::new();
        two.insert("y.js".to_owned(), b);
        two.insert("x.js".to_owned(), a);
        assert_eq!(snapshot_digest(&one), snapshot_digest(&two));
        two.insert("y.js".to_owned(), a);
        assert_ne!(snapshot_digest(&one), snapshot_digest(&two));
    }
}
