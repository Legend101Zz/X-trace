//! Transactional storage for the bounded catalog-discovery transcript.
//!
//! This adapter accepts only the opaque application admission token. The
//! shipped application refuses admission, so no producer claim can create
//! catalog state until owner selection, verified-pack, and source authorities
//! are wired into that boundary.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::sync::{Arc, Mutex};

use rusqlite::{OptionalExtension as _, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use xtrace_application::{
    AdmittedCatalogSelection, CatalogChangeKind, CatalogDiscoveryWritePort, CatalogOperationFilter,
    CatalogOperationRecord, CatalogReadPort, CatalogRevisionSummary, CatalogRunNamespace,
    CatalogSourceAvailability, PortError, PortErrorKind,
};
use xtrace_domain::catalog_discovery::{
    ClaimProvenance, ClaimSourceEvidence, DiscoveryChunk, DiscoveryCompletion, DiscoveryProofError,
    DiscoveryRunFinish, DiscoveryRunGrant, DiscoveryRunStartRequest, DiscoveryScope,
    DiscoveryScopeKind,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    CatalogRevisionId, ClaimId, ContentHash, CorrelationId, EndpointIdentity, HttpMethod,
    OperationId, OperationVersionId, ProjectId, RunId, SourceRevisionId, Transport,
};

use crate::connection::SqliteStore;
use crate::error::{StoreError, StoreErrorKind};

/// Store view over catalog-discovery transactions.
#[derive(Clone, Debug)]
pub struct SqliteCatalogDiscoveryStore {
    store: SqliteStore,
    #[cfg(test)]
    test_now: Arc<Mutex<Option<String>>>,
}

/// Private transaction input copied from the application's opaque admission
/// token. Store tests can construct this view; production callers cannot pass
/// one through the public port or create an application authority token.
#[derive(Clone, Debug)]
struct SelectionView {
    project_id: ProjectId,
    runtime_session_id: xtrace_domain::RuntimeSessionId,
    verified_pack_digest: ContentHash,
    protocol_minor: u32,
    namespace: CatalogRunNamespace,
    owner_selection_id: [u8; 16],
    owner_selection_epoch: u64,
    scope: DiscoveryScope,
    source_revision_id: Option<SourceRevisionId>,
    pinned_source_digest: Option<ContentHash>,
}

impl From<&AdmittedCatalogSelection> for SelectionView {
    fn from(selection: &AdmittedCatalogSelection) -> Self {
        Self {
            project_id: selection.project_id(),
            runtime_session_id: selection.runtime_session_id(),
            verified_pack_digest: selection.verified_pack_digest(),
            protocol_minor: selection.protocol_minor(),
            namespace: selection.namespace(),
            owner_selection_id: *selection.owner_selection_id(),
            owner_selection_epoch: selection.owner_selection_epoch(),
            scope: selection.scope().clone(),
            source_revision_id: selection.source_revision_id(),
            pinned_source_digest: selection.pinned_source_digest(),
        }
    }
}

impl SelectionView {
    const fn project_id(&self) -> ProjectId {
        self.project_id
    }
    const fn runtime_session_id(&self) -> xtrace_domain::RuntimeSessionId {
        self.runtime_session_id
    }
    const fn verified_pack_digest(&self) -> ContentHash {
        self.verified_pack_digest
    }
    const fn protocol_minor(&self) -> u32 {
        self.protocol_minor
    }
    const fn namespace(&self) -> CatalogRunNamespace {
        self.namespace
    }
    const fn owner_selection_id(&self) -> &[u8; 16] {
        &self.owner_selection_id
    }
    const fn owner_selection_epoch(&self) -> u64 {
        self.owner_selection_epoch
    }
    fn scope(&self) -> &DiscoveryScope {
        &self.scope
    }
    const fn source_revision_id(&self) -> Option<SourceRevisionId> {
        self.source_revision_id
    }
    const fn pinned_source_digest(&self) -> Option<ContentHash> {
        self.pinned_source_digest
    }
}

impl SqliteCatalogDiscoveryStore {
    /// Creates a catalog view over the shared SQLite handle.
    #[must_use]
    pub fn new(store: SqliteStore) -> Self {
        Self {
            store,
            #[cfg(test)]
            test_now: Arc::new(Mutex::new(None)),
        }
    }

    fn now(&self) -> String {
        #[cfg(test)]
        if let Ok(value) = self.test_now.lock()
            && let Some(value) = value.as_ref()
        {
            return value.clone();
        }
        xtrace_domain::WallTime::now().to_rfc3339()
    }

    #[cfg(test)]
    fn set_test_now(&self, value: &str) {
        if let Ok(mut current) = self.test_now.lock() {
            *current = Some(value.to_owned());
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredClaim {
    claim_hint: String,
    project_id: ProjectId,
    application_component: String,
    binding_key: String,
    method: HttpMethod,
    route_template: String,
    provenance: ClaimProvenance,
    handler_symbol: Option<String>,
    confidence_basis_points: Option<u16>,
    limitation_codes: Vec<String>,
    source_evidence: Vec<ClaimSourceEvidence>,
}

impl StoredClaim {
    fn from_claim(claim: &xtrace_domain::catalog_discovery::ValidatedEndpointClaim) -> Self {
        Self {
            claim_hint: claim.claim_hint().to_owned(),
            project_id: claim.operation().project_id,
            application_component: claim.operation().application_component.clone(),
            binding_key: claim.operation().binding_key.clone(),
            method: claim.operation().method,
            route_template: claim.operation().route_template.clone(),
            provenance: claim.provenance(),
            handler_symbol: claim.handler_symbol().map(str::to_owned),
            confidence_basis_points: claim.confidence_basis_points(),
            limitation_codes: claim.limitation_codes().to_vec(),
            source_evidence: claim.source_evidence().to_vec(),
        }
    }

    fn rebuild(
        self,
    ) -> Result<xtrace_domain::catalog_discovery::ValidatedEndpointClaim, DiscoveryProofError> {
        let operation = EndpointIdentity {
            project_id: self.project_id,
            application_component: self.application_component,
            transport: Transport::Http,
            binding_key: self.binding_key,
            method: self.method,
            route_template: self.route_template,
        };
        xtrace_domain::catalog_discovery::ValidatedEndpointClaim::from_persisted(
            self.claim_hint,
            operation,
            self.provenance,
            self.handler_symbol,
            self.confidence_basis_points,
            self.limitation_codes,
            self.source_evidence,
        )
    }
}

struct RunRow {
    project_id: ProjectId,
    session_id: xtrace_domain::RuntimeSessionId,
    pack_digest: ContentHash,
    protocol_minor: u32,
    owner_selection_id: [u8; 16],
    selection_epoch: u64,
    namespace: String,
    started_at: Option<String>,
    expires_at: Option<String>,
    expired_at: Option<String>,
    scope_digest: ContentHash,
    scope: DiscoveryScope,
    source_revision_id: Option<SourceRevisionId>,
    pinned_source_digest: Option<ContentHash>,
    accepted_claim_count: u32,
    accepted_claim_bytes: u32,
    status: String,
}

impl CatalogDiscoveryWritePort for SqliteCatalogDiscoveryStore {
    fn start_run(
        &self,
        selection: &AdmittedCatalogSelection,
        request: &DiscoveryRunStartRequest,
    ) -> Result<DiscoveryRunGrant, PortError> {
        self.start_run_with_view(&SelectionView::from(selection), request)
    }

    fn submit_chunk(
        &self,
        selection: &AdmittedCatalogSelection,
        chunk: &DiscoveryChunk,
    ) -> Result<(), PortError> {
        self.submit_chunk_with_view(&SelectionView::from(selection), chunk)
    }

    fn finish_run(
        &self,
        selection: &AdmittedCatalogSelection,
        finish: &DiscoveryRunFinish,
    ) -> Result<(), PortError> {
        self.finish_run_with_view(&SelectionView::from(selection), finish)
    }
}

impl SqliteCatalogDiscoveryStore {
    fn start_run_with_view(
        &self,
        selection: &SelectionView,
        request: &DiscoveryRunStartRequest,
    ) -> Result<DiscoveryRunGrant, PortError> {
        request.validate().map_err(|_| validation_error())?;
        if request.requested_scope.canonical_bytes().map_err(|_| validation_error())?
            != selection.scope().canonical_bytes().map_err(|_| validation_error())?
        {
            return Err(conflict_error());
        }
        let correlation_id = CorrelationId::new();
        let mut connection = self.store.lock().map_err(map_store_error)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        let started_at = self.now();
        // Exact retries are checked against their original immutable
        // selection even if a newer selection now covers the same scope.
        verify_selection(&transaction, selection, false)?;
        let request_bytes = request.canonical_bytes().map_err(|_| validation_error())?;
        let request_digest = ContentHash::of_bytes(&request_bytes);
        if let Some(existing) = transaction
            .query_row(
                "SELECT r.run_id, r.request_bytes, r.request_digest, r.scope_digest, r.source_revision_id, r.protocol_minor, r.pinned_source_digest, r.status, d.expires_at, d.started_at, d.expired_at, r.run_hint, k.stored_run_hint FROM catalog_discovery_retry_keys k JOIN catalog_discovery_runs r ON r.run_id = k.run_id LEFT JOIN catalog_discovery_run_deadlines d ON d.run_id = r.run_id \
                 WHERE k.project_id = ?1 AND k.runtime_session_id = ?2 AND k.verified_pack_digest = ?3 \
                   AND k.retry_namespace = ?4 AND k.request_run_hint = ?5",
                params![
                    selection.project_id().as_uuid().as_bytes().to_vec(),
                    selection.runtime_session_id().as_uuid().as_bytes().to_vec(),
                    selection.verified_pack_digest().as_bytes().to_vec(),
                    selection.namespace().storage_key(),
                    request.run_hint,
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Option<Vec<u8>>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, Option<String>>(10)?,
                        row.get::<_, String>(11)?,
                        row.get::<_, String>(12)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| map_rusqlite(error, correlation_id))?
        {
            let expected_stored_hint = stored_run_hint(selection.namespace(), &request.run_hint);
            if existing.11 != expected_stored_hint || existing.12 != expected_stored_hint {
                return Err(corruption_error());
            }
            if existing.1 != request_bytes {
                return Err(conflict_error());
            }
            let run_id = decode_id::<RunId>(&existing.0).ok_or_else(corruption_error)?;
            let run = load_run(&transaction, run_id)?;
            verify_run_selection(&transaction, selection, &run, false)?;
            if existing.7 == "open"
                && (existing.10.is_some() || is_expired(
                    existing.9.as_deref().ok_or_else(corruption_error)?,
                    existing.8.as_deref().ok_or_else(corruption_error)?,
                    &started_at,
                )?)
            {
                mark_expired(&transaction, &existing.0, &started_at, correlation_id)?;
                transaction.commit().map_err(|error| map_rusqlite(error, correlation_id))?;
                return Err(conflict_error());
            }
            if !matches!(existing.7.as_str(), "open" | "complete" | "incomplete" | "failed" | "superseded") {
                return Err(conflict_error());
            }
            let expected_revision =
                selection.source_revision_id().map(|id| id.as_uuid().as_bytes().to_vec());
            let expected_source_digest =
                selection.pinned_source_digest().map(|hash| hash.as_bytes().to_vec());
            if ContentHash::from_digest_bytes(&existing.2) != Some(ContentHash::of_bytes(&existing.1))
                || existing.3.as_deref().and_then(ContentHash::from_digest_bytes)
                    != selection.scope().digest().ok()
                || u32::try_from(existing.5).ok() != Some(selection.protocol_minor())
                || existing.4.as_deref() != expected_revision.as_deref()
                || existing.6.as_deref() != expected_source_digest.as_deref()
            {
                return Err(corruption_error());
            }
            let scope_digest = existing
                .3
                .as_deref()
                .and_then(ContentHash::from_digest_bytes)
                .ok_or_else(corruption_error)?;
            let source_revision_id = match existing.4.as_deref() {
                Some(bytes) => Some(decode_id::<SourceRevisionId>(bytes).ok_or_else(corruption_error)?),
                None => None,
            };
            transaction.commit().map_err(|error| map_rusqlite(error, correlation_id))?;
            return Ok(DiscoveryRunGrant::Admitted { run_id, scope_digest, source_revision_id });
        }

        // v0005 rows have no retry-namespace record. Never silently adopt an
        // old hint into a new namespace or replay authority across versions.
        let legacy_retry: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM catalog_discovery_runs WHERE project_id = ?1 AND runtime_session_id = ?2 AND verified_pack_digest = ?3 AND owner_selection_id = ?4 AND run_hint = ?5)",
                params![selection.project_id().as_uuid().as_bytes().to_vec(), selection.runtime_session_id().as_uuid().as_bytes().to_vec(), selection.verified_pack_digest().as_bytes().to_vec(), selection.owner_selection_id().to_vec(), request.run_hint],
                |row| row.get(0),
            )
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        if legacy_retry {
            return Err(conflict_error());
        }
        let orphaned_retry: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM catalog_discovery_runs WHERE project_id = ?1 AND runtime_session_id = ?2 AND verified_pack_digest = ?3 AND owner_selection_id = ?4 AND run_hint = ?5)",
                params![selection.project_id().as_uuid().as_bytes().to_vec(), selection.runtime_session_id().as_uuid().as_bytes().to_vec(), selection.verified_pack_digest().as_bytes().to_vec(), selection.owner_selection_id().to_vec(), stored_run_hint(selection.namespace(), &request.run_hint)],
                |row| row.get(0),
            )
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        if orphaned_retry {
            return Err(corruption_error());
        }

        verify_selection(&transaction, selection, true)?;
        let run_id = RunId::new();
        let expires_at = expiry_from(&started_at)?;
        let request_hint = request.run_hint.clone();
        let stored_run_hint = stored_run_hint(selection.namespace(), &request_hint);
        let scope_digest = selection.scope().digest().map_err(|_| validation_error())?;
        let scope_json =
            serde_json::to_string(selection.scope()).map_err(|_| validation_error())?;
        let source_revision_id = selection.source_revision_id();
        let pinned_source_digest = selection.pinned_source_digest();
        transaction
            .execute(
                "INSERT INTO catalog_discovery_runs \
                 (run_id, project_id, runtime_session_id, verified_pack_digest, protocol_minor, owner_selection_id, selection_epoch, \
                  run_hint, request_bytes, request_digest, scope_digest, scope_json, source_revision_id, pinned_source_digest, status) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 'open')",
                params![
                    run_id.as_uuid().as_bytes().to_vec(),
                    selection.project_id().as_uuid().as_bytes().to_vec(),
                    selection.runtime_session_id().as_uuid().as_bytes().to_vec(),
                    selection.verified_pack_digest().as_bytes().to_vec(),
                    i64::from(selection.protocol_minor()),
                    selection.owner_selection_id().to_vec(),
                    i64::try_from(selection.owner_selection_epoch()).map_err(|_| validation_error())?,
                    stored_run_hint,
                    request_bytes,
                    request_digest.as_bytes().to_vec(),
                    scope_digest.as_bytes().to_vec(),
                    scope_json,
                    source_revision_id.map(|id| id.as_uuid().as_bytes().to_vec()),
                    pinned_source_digest.map(|hash| hash.as_bytes().to_vec()),
                ],
            )
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        transaction
            .execute(
                "INSERT INTO catalog_discovery_retry_keys (project_id, runtime_session_id, verified_pack_digest, retry_namespace, request_run_hint, stored_run_hint, run_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![selection.project_id().as_uuid().as_bytes().to_vec(), selection.runtime_session_id().as_uuid().as_bytes().to_vec(), selection.verified_pack_digest().as_bytes().to_vec(), selection.namespace().storage_key(), request_hint, stored_run_hint, run_id.as_uuid().as_bytes().to_vec()],
            )
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        transaction
            .execute(
                "INSERT INTO catalog_discovery_run_deadlines (run_id, project_id, started_at, expires_at, expired_at) VALUES (?1, ?2, ?3, ?4, NULL)",
                params![run_id.as_uuid().as_bytes().to_vec(), selection.project_id().as_uuid().as_bytes().to_vec(), started_at, expires_at],
            )
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        transaction.commit().map_err(|error| map_rusqlite(error, correlation_id))?;
        Ok(DiscoveryRunGrant::Admitted { run_id, scope_digest, source_revision_id })
    }

    fn submit_chunk_with_view(
        &self,
        selection: &SelectionView,
        chunk: &DiscoveryChunk,
    ) -> Result<(), PortError> {
        let canonical_chunk = chunk.canonical_bytes().map_err(|_| validation_error())?;
        let digest = ContentHash::of_bytes(&canonical_chunk);
        // The application port (`CatalogSourceProofPort`) is the authority on source proof: the
        // default refuses every static or class-bound claim and only the local-scan wiring re-reads
        // the pinned bytes. The store keeps a cheap independent invariant behind it: a static
        // snapshot claim must cite exactly the snapshot the selection pinned, and a class-bound
        // claim is never stored in the local-scan namespace (it has no loaded classes).
        if chunk.claims.iter().any(|claim| {
            claim.source_evidence().iter().any(|evidence| match evidence {
                ClaimSourceEvidence::StaticSnapshot { source_revision_id, .. } => {
                    Some(*source_revision_id) != selection.source_revision_id()
                }
                ClaimSourceEvidence::LoadedClassBound { .. } => {
                    matches!(selection.namespace(), CatalogRunNamespace::LocalStaticScanner)
                }
                _ => false,
            })
        }) {
            return Err(refusal_error());
        }
        if chunk.claims.iter().any(|claim| {
            claim.operation().project_id != selection.project_id()
                || claim.operation().application_component
                    != selection.scope().application_component
                || claim.operation().binding_key != selection.scope().binding_key
                || !provenance_matches_scope(claim.provenance(), selection.scope())
        }) {
            return Err(validation_error());
        }
        let claims = chunk
            .claims
            .iter()
            .map(|claim| {
                let stored = StoredClaim::from_claim(claim);
                let json = serde_json::to_string(&stored).map_err(|_| validation_error())?;
                Ok((
                    stored,
                    json,
                    claim.canonical_bytes().to_vec(),
                    claim.digest().ok_or_else(validation_error)?,
                ))
            })
            .collect::<Result<Vec<_>, PortError>>()?;
        let payload_bytes = claims.iter().try_fold(0_usize, |sum, value| {
            sum.checked_add(value.2.len()).ok_or_else(validation_error)
        })?;
        let correlation_id = CorrelationId::new();
        let mut connection = self.store.lock().map_err(map_store_error)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        let run = load_run(&transaction, chunk.run_id)?;
        verify_run_selection(&transaction, selection, &run, true)?;
        if run.status != "open" {
            return Err(conflict_error());
        }
        let now = self.now();
        if run.expired_at.is_some()
            || is_expired(
                run.started_at.as_deref().ok_or_else(corruption_error)?,
                run.expires_at.as_deref().ok_or_else(corruption_error)?,
                &now,
            )?
        {
            mark_expired(&transaction, chunk.run_id.as_uuid().as_bytes(), &now, correlation_id)?;
            transaction.commit().map_err(|error| map_rusqlite(error, correlation_id))?;
            return Err(conflict_error());
        }
        let existing = transaction
            .query_row(
                "SELECT chunk_digest FROM catalog_discovery_chunks WHERE run_id = ?1 AND chunk_index = ?2",
                params![chunk.run_id.as_uuid().as_bytes().to_vec(), i64::from(chunk.chunk_index)],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        if let Some(existing_digest) = existing {
            if existing_digest == digest.as_bytes() {
                transaction.commit().map_err(|error| map_rusqlite(error, correlation_id))?;
                return Ok(());
            }
            transaction
                .execute(
                    "UPDATE catalog_discovery_runs SET status = 'invalid' WHERE run_id = ?1 AND status = 'open'",
                    params![chunk.run_id.as_uuid().as_bytes().to_vec()],
                )
                .map_err(|error| map_rusqlite(error, correlation_id))?;
            transaction.commit().map_err(|error| map_rusqlite(error, correlation_id))?;
            return Err(conflict_error());
        }
        let mut hints = BTreeSet::new();
        let mut digests = BTreeSet::new();
        let mut duplicate_claim = false;
        for claim in &claims {
            if !hints.insert(claim.0.claim_hint.as_str())
                || !digests.insert(claim.3.as_bytes().to_vec())
            {
                duplicate_claim = true;
                break;
            }
            let already_seen: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM catalog_discovery_claims WHERE run_id = ?1 AND claim_hint = ?2)",
                    params![chunk.run_id.as_uuid().as_bytes().to_vec(), claim.0.claim_hint.as_str()],
                    |row| row.get(0),
                )
                .map_err(|error| map_rusqlite(error, correlation_id))?;
            if already_seen {
                duplicate_claim = true;
                break;
            }
            let digest_already_seen: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM catalog_discovery_claims WHERE run_id = ?1 AND claim_digest = ?2)",
                    params![chunk.run_id.as_uuid().as_bytes().to_vec(), claim.3.as_bytes().to_vec()],
                    |row| row.get(0),
                )
                .map_err(|error| map_rusqlite(error, correlation_id))?;
            if digest_already_seen {
                duplicate_claim = true;
                break;
            }
        }
        if duplicate_claim {
            transaction
                .execute(
                    "UPDATE catalog_discovery_runs SET status = 'invalid' WHERE run_id = ?1 AND status = 'open'",
                    params![chunk.run_id.as_uuid().as_bytes().to_vec()],
                )
                .map_err(|error| map_rusqlite(error, correlation_id))?;
            transaction.commit().map_err(|error| map_rusqlite(error, correlation_id))?;
            return Err(conflict_error());
        }
        let (prior_claims, prior_bytes): (i64, i64) = transaction
            .query_row(
                "SELECT COALESCE(SUM(claim_count), 0), COALESCE(SUM(payload_bytes), 0) \
                 FROM catalog_discovery_chunks WHERE run_id = ?1",
                params![chunk.run_id.as_uuid().as_bytes().to_vec()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        let total_claims =
            usize::try_from(prior_claims).ok().and_then(|count| count.checked_add(claims.len()));
        let total_bytes =
            usize::try_from(prior_bytes).ok().and_then(|bytes| bytes.checked_add(payload_bytes));
        if total_claims.is_none_or(|count| count > 4096)
            || total_bytes.is_none_or(|bytes| bytes > 4 * 1024 * 1024)
        {
            return Err(validation_error());
        }
        transaction
            .execute(
                "INSERT INTO catalog_discovery_chunks (run_id, project_id, chunk_index, chunk_digest, claim_count, payload_bytes) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    chunk.run_id.as_uuid().as_bytes().to_vec(),
                    selection.project_id().as_uuid().as_bytes().to_vec(),
                    i64::from(chunk.chunk_index),
                    digest.as_bytes().to_vec(),
                    i64::try_from(claims.len()).map_err(|_| validation_error())?,
                    i64::try_from(payload_bytes).map_err(|_| validation_error())?,
                ],
            )
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        for (ordinal, (stored, json, canonical, claim_digest)) in claims.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO catalog_discovery_claims (run_id, project_id, chunk_index, claim_ordinal, claim_hint, claim_digest, canonical_bytes, canonical_json) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        chunk.run_id.as_uuid().as_bytes().to_vec(),
                        selection.project_id().as_uuid().as_bytes().to_vec(),
                        i64::from(chunk.chunk_index),
                        i64::try_from(ordinal).map_err(|_| validation_error())?,
                        stored.claim_hint,
                        claim_digest.as_bytes().to_vec(),
                        canonical,
                        json,
                    ],
                )
                .map_err(|error| map_rusqlite(error, correlation_id))?;
        }
        transaction
            .execute(
                "UPDATE catalog_discovery_runs SET accepted_claim_count = accepted_claim_count + ?2, accepted_claim_bytes = accepted_claim_bytes + ?3 \
                 WHERE run_id = ?1 AND status = 'open'",
                params![chunk.run_id.as_uuid().as_bytes().to_vec(), i64::try_from(claims.len()).map_err(|_| validation_error())?, i64::try_from(payload_bytes).map_err(|_| validation_error())?],
            )
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        transaction.commit().map_err(|error| map_rusqlite(error, correlation_id))
    }

    fn finish_run_with_view(
        &self,
        selection: &SelectionView,
        finish: &DiscoveryRunFinish,
    ) -> Result<(), PortError> {
        let correlation_id = CorrelationId::new();
        let mut connection = self.store.lock().map_err(map_store_error)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        let run = load_run(&transaction, finish.run_id)?;
        verify_run_selection(&transaction, selection, &run, false)?;
        let status = match finish.completion {
            DiscoveryCompletion::Complete => "complete",
            DiscoveryCompletion::Incomplete => "incomplete",
            DiscoveryCompletion::Failed => "failed",
        };
        let limitation_json =
            serde_json::to_string(&finish.limitation_codes).map_err(|_| validation_error())?;
        if run.status == "open"
            && (run.expired_at.is_some()
                || is_expired(
                    run.started_at.as_deref().ok_or_else(corruption_error)?,
                    run.expires_at.as_deref().ok_or_else(corruption_error)?,
                    &self.now(),
                )?)
        {
            let now = self.now();
            mark_expired(&transaction, finish.run_id.as_uuid().as_bytes(), &now, correlation_id)?;
            transaction.commit().map_err(|error| map_rusqlite(error, correlation_id))?;
            return Err(conflict_error());
        }
        let chunks = load_and_verify_chunks(
            &transaction,
            finish.run_id,
            selection.project_id(),
            &run.scope,
        )?;
        let actual_claim_count = chunks.iter().map(|chunk| chunk.claims.len()).sum::<usize>();
        let actual_claim_bytes = chunks
            .iter()
            .flat_map(|chunk| &chunk.claims)
            .try_fold(0_usize, |total, claim| total.checked_add(claim.canonical_bytes().len()))
            .ok_or_else(corruption_error)?;
        if usize::try_from(run.accepted_claim_count).ok() != Some(actual_claim_count)
            || usize::try_from(run.accepted_claim_bytes).ok() != Some(actual_claim_bytes)
        {
            return Err(corruption_error());
        }
        finish
            .validate_against(&run.scope, run.source_revision_id, &chunks)
            .map_err(|_| validation_error())?;
        if run.status != "open" {
            let existing = transaction.query_row(
                "SELECT expected_chunk_count, accepted_claim_count, rejected_claim_count, final_digest, limitation_codes_json \
                 FROM catalog_discovery_runs WHERE run_id = ?1",
                params![finish.run_id.as_uuid().as_bytes().to_vec()],
                |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, Option<Vec<u8>>>(3)?, row.get::<_, Option<String>>(4)?)),
            ).map_err(|error| map_rusqlite(error, correlation_id))?;
            if (run.status == status || (run.status == "superseded" && status == "complete"))
                && existing.0 == Some(i64::from(finish.expected_chunk_count))
                && existing.1 == i64::from(finish.accepted_claim_count)
                && existing.2 == i64::from(finish.rejected_claim_count)
                && existing.3.as_deref() == Some(finish.final_digest.as_bytes().as_slice())
                && existing.4.as_deref() == Some(limitation_json.as_str())
            {
                transaction.commit().map_err(|error| map_rusqlite(error, correlation_id))?;
                return Ok(());
            }
            return Err(conflict_error());
        }
        if finish.completion != DiscoveryCompletion::Complete {
            transaction
                .execute(
                    "UPDATE catalog_discovery_runs SET status = ?2, expected_chunk_count = ?3, rejected_claim_count = ?4, final_digest = ?5, limitation_codes_json = ?6 \
                     WHERE run_id = ?1 AND status = 'open'",
                    params![
                        finish.run_id.as_uuid().as_bytes().to_vec(),
                        status,
                        i64::from(finish.expected_chunk_count),
                        i64::from(finish.rejected_claim_count),
                        finish.final_digest.as_bytes().to_vec(),
                        limitation_json,
                    ],
                )
                .map_err(|error| map_rusqlite(error, correlation_id))?;
            transaction.commit().map_err(|error| map_rusqlite(error, correlation_id))?;
            return Ok(());
        }

        // Read the revocation row in this same write transaction, then store
        // a superseded historical receipt without publishing current scope.
        verify_selection(&transaction, selection, false)?;
        let current_for_scope: i64 = transaction
            .query_row(
                "SELECT current_for_scope FROM catalog_owner_selections WHERE owner_selection_id = ?1 AND project_id = ?2 AND selection_epoch = ?3",
                params![selection.owner_selection_id().to_vec(), selection.project_id().as_uuid().as_bytes().to_vec(), i64::try_from(selection.owner_selection_epoch()).map_err(|_| validation_error())?],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| map_rusqlite(error, correlation_id))?
            .ok_or_else(refusal_error)?;
        if current_for_scope != 1 {
            transaction
                .execute(
                    "UPDATE catalog_discovery_runs SET status = 'superseded', expected_chunk_count = ?2, rejected_claim_count = ?3, final_digest = ?4, limitation_codes_json = ?5 \
                     WHERE run_id = ?1 AND status = 'open'",
                    params![finish.run_id.as_uuid().as_bytes().to_vec(), i64::from(finish.expected_chunk_count), i64::from(finish.rejected_claim_count), finish.final_digest.as_bytes().to_vec(), limitation_json],
                )
                .map_err(|error| map_rusqlite(error, correlation_id))?;
            transaction.commit().map_err(|error| map_rusqlite(error, correlation_id))?;
            return Ok(());
        }
        publish_revision(
            &transaction,
            selection,
            &run,
            finish,
            &chunks,
            &limitation_json,
            correlation_id,
        )?;
        transaction.commit().map_err(|error| map_rusqlite(error, correlation_id))
    }
}

impl CatalogReadPort for SqliteCatalogDiscoveryStore {
    fn read_revision_summary(
        &self,
        project_id: ProjectId,
        revision_id: CatalogRevisionId,
    ) -> Result<CatalogRevisionSummary, PortError> {
        let correlation_id = CorrelationId::new();
        let connection = self.store.lock().map_err(map_store_error)?;
        let summary = connection
            .query_row(
                "SELECT r.scope_digest, r.operation_count, r.final_digest, r.source_revision_id, d.status, d.revision_id, d.final_digest, d.source_revision_id \
                 FROM catalog_revisions r JOIN catalog_discovery_runs d ON d.run_id = r.run_id AND d.project_id = r.project_id \
                 WHERE r.project_id = ?1 AND r.revision_id = ?2",
                params![project_id.as_uuid().as_bytes().to_vec(), revision_id.as_uuid().as_bytes().to_vec()],
                |row| Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                )),
            )
            .optional()
            .map_err(|error| map_rusqlite(error, correlation_id))?
            .ok_or_else(|| PortError::new(PortErrorKind::NotFound, "catalog revision was not found", correlation_id))?;
        let scope_digest =
            ContentHash::from_digest_bytes(&summary.0).ok_or_else(corruption_error)?;
        let completion = match summary.4.as_str() {
            "complete" => DiscoveryCompletion::Complete,
            "incomplete" => DiscoveryCompletion::Incomplete,
            "failed" => DiscoveryCompletion::Failed,
            _ => return Err(corruption_error()),
        };
        if summary.4 != "complete"
            || summary.5.as_deref() != Some(revision_id.as_uuid().as_bytes())
            || summary.6.as_deref() != Some(summary.2.as_slice())
            || summary.3.as_deref() != summary.7.as_deref()
        {
            return Err(corruption_error());
        }
        let source_revision_id = match summary.3.as_deref() {
            Some(bytes) => Some(decode_id::<SourceRevisionId>(bytes).ok_or_else(corruption_error)?),
            None => None,
        };
        Ok(CatalogRevisionSummary {
            project_id,
            revision_id,
            scope_digest,
            source_revision_id,
            completion,
            operation_count: u32::try_from(summary.1).map_err(|_| corruption_error())?,
        })
    }

    fn list_revision_operations(
        &self,
        project_id: ProjectId,
        revision_id: CatalogRevisionId,
        filter: CatalogOperationFilter,
        after: Option<OperationId>,
        limit: u32,
    ) -> Result<(Vec<CatalogOperationRecord>, bool), PortError> {
        if !(1..=100).contains(&limit)
            || after.is_some_and(|id| {
                id.as_uuid().get_version_num() != 7
                    || id.as_uuid().get_variant() != uuid::Variant::RFC4122
            })
        {
            return Err(validation_error());
        }
        let correlation_id = CorrelationId::new();
        let connection = self.store.lock().map_err(map_store_error)?;
        let revision_status = connection
            .query_row(
                "SELECT d.status FROM catalog_revisions r JOIN catalog_discovery_runs d ON d.run_id = r.run_id AND d.project_id = r.project_id \
                 WHERE r.project_id = ?1 AND r.revision_id = ?2 AND d.revision_id = r.revision_id AND d.final_digest = r.final_digest",
                params![project_id.as_uuid().as_bytes().to_vec(), revision_id.as_uuid().as_bytes().to_vec()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| map_rusqlite(error, correlation_id))?
            .ok_or_else(|| PortError::new(PortErrorKind::NotFound, "catalog revision was not found", correlation_id))?;
        if revision_status != "complete" {
            return Err(corruption_error());
        }
        let change_kind = filter.change_kind.map(CatalogChangeKind::as_str);
        let after_bytes = after.map(|id| id.as_uuid().as_bytes().to_vec());
        let mut statement = connection
            .prepare(
                "SELECT e.operation_id, o.application_component, o.binding_key, o.method, o.route_template, e.change_kind, e.source_availability, o.endpoint_fingerprint \
                 FROM catalog_revision_entries e JOIN catalog_operations o ON o.project_id = e.project_id AND o.operation_id = e.operation_id \
                 WHERE e.project_id = ?1 AND e.revision_id = ?2 AND (?3 IS NULL OR e.change_kind = ?3) \
                   AND (?4 IS NULL OR e.operation_id > ?4) ORDER BY e.operation_id LIMIT ?5",
            )
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        let raw_rows = statement
            .query_map(
                params![
                    project_id.as_uuid().as_bytes().to_vec(),
                    revision_id.as_uuid().as_bytes().to_vec(),
                    change_kind,
                    after_bytes,
                    i64::from(limit) + 1,
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                    ))
                },
            )
            .map_err(|error| map_rusqlite(error, correlation_id))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        let has_more = raw_rows.len() > limit as usize;
        let mut records = Vec::with_capacity(raw_rows.len().min(limit as usize));
        for (
            operation_bytes,
            component,
            binding,
            method,
            route,
            change,
            availability,
            stored_fingerprint,
        ) in raw_rows.into_iter().take(limit as usize)
        {
            let operation_id =
                decode_id::<OperationId>(&operation_bytes).ok_or_else(corruption_error)?;
            let identity = EndpointIdentity {
                project_id,
                application_component: component.clone(),
                transport: Transport::Http,
                binding_key: binding.clone(),
                method: HttpMethod::parse(&method).ok_or_else(corruption_error)?,
                route_template: route.clone(),
            };
            if identity.fingerprint().ok().map(|hash| hash.as_bytes().to_vec())
                != Some(stored_fingerprint)
            {
                return Err(corruption_error());
            }
            let change_kind = match change.as_str() {
                "added" => CatalogChangeKind::Added,
                "unchanged" => CatalogChangeKind::Unchanged,
                "changed" => CatalogChangeKind::Changed,
                "removed" => CatalogChangeKind::Removed,
                "unknown" => CatalogChangeKind::Unknown,
                _ => return Err(corruption_error()),
            };
            let source_availability = match availability.as_str() {
                "unverified" => CatalogSourceAvailability::Unverified,
                "unavailable" => CatalogSourceAvailability::Unavailable,
                _ => return Err(corruption_error()),
            };
            let mut provenance = Vec::new();
            let mut limitation_codes = BTreeSet::new();
            let claim_bounds: (i64, i64) = connection
                .query_row(
                    "SELECT COUNT(*), COALESCE(SUM(length(CAST(c.canonical_json AS BLOB))), 0) \
                     FROM catalog_revision_claims rc JOIN catalog_claims c ON c.project_id = rc.project_id AND c.operation_id = rc.operation_id AND c.claim_id = rc.claim_id \
                     WHERE rc.project_id = ?1 AND rc.revision_id = ?2 AND rc.operation_id = ?3",
                    params![project_id.as_uuid().as_bytes().to_vec(), revision_id.as_uuid().as_bytes().to_vec(), operation_id.as_uuid().as_bytes().to_vec()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|error| map_rusqlite(error, correlation_id))?;
            if claim_bounds.0 > 4096 || claim_bounds.1 > 4 * 1024 * 1024 {
                return Err(corruption_error());
            }
            let mut claim_statement = connection
                .prepare(
                    "SELECT c.claim_digest, c.canonical_bytes, c.canonical_json FROM catalog_revision_claims rc \
                     JOIN catalog_claims c ON c.project_id = rc.project_id AND c.operation_id = rc.operation_id AND c.claim_id = rc.claim_id \
                     WHERE rc.project_id = ?1 AND rc.revision_id = ?2 AND rc.operation_id = ?3 ORDER BY c.claim_id LIMIT 4097",
                )
                .map_err(|error| map_rusqlite(error, correlation_id))?;
            let claims = claim_statement
                .query_map(
                    params![
                        project_id.as_uuid().as_bytes().to_vec(),
                        revision_id.as_uuid().as_bytes().to_vec(),
                        operation_id.as_uuid().as_bytes().to_vec()
                    ],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .map_err(|error| map_rusqlite(error, correlation_id))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| map_rusqlite(error, correlation_id))?;
            if claims.len() as i64 != claim_bounds.0 {
                return Err(corruption_error());
            }
            for (claim_digest, canonical_bytes, json) in claims {
                if canonical_bytes.len() > 8192 || json.len() > 16 * 1024 {
                    return Err(corruption_error());
                }
                let stored: StoredClaim =
                    serde_json::from_str(&json).map_err(|_| corruption_error())?;
                let claim = stored.rebuild().map_err(|_| corruption_error())?;
                if claim.canonical_bytes() != canonical_bytes
                    || claim.digest().map(|digest| digest.as_bytes().to_vec()) != Some(claim_digest)
                    || claim.operation().project_id != project_id
                    || claim.operation().application_component != component
                    || claim.operation().binding_key != binding
                    || claim.operation().method.as_str() != method
                    || claim.operation().route_template != route
                {
                    return Err(corruption_error());
                }
                let claim_provenance = claim.provenance();
                if !provenance.contains(&claim_provenance) {
                    provenance.push(claim_provenance);
                }
                limitation_codes.extend(claim.limitation_codes().iter().cloned());
            }
            records.push(CatalogOperationRecord {
                operation_id,
                provenance,
                limitation_codes: limitation_codes.into_iter().collect(),
                change_kind,
                source_availability,
            });
        }
        Ok((records, has_more))
    }
}

fn verify_selection(
    transaction: &Transaction<'_>,
    selection: &SelectionView,
    require_current: bool,
) -> Result<(), PortError> {
    let row = transaction
        .query_row(
            "SELECT verified_pack_digest, scope_digest, scope_json, source_revision_id, pinned_source_digest, revoked, current_for_scope \
             FROM catalog_owner_selections WHERE owner_selection_id = ?1 AND project_id = ?2 AND selection_epoch = ?3",
            params![selection.owner_selection_id().to_vec(), selection.project_id().as_uuid().as_bytes().to_vec(), i64::try_from(selection.owner_selection_epoch()).map_err(|_| validation_error())?],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<Vec<u8>>>(3)?, row.get::<_, Option<Vec<u8>>>(4)?, row.get::<_, i64>(5)?, row.get::<_, i64>(6)?)),
        )
        .optional()
        .map_err(|error| map_rusqlite(error, CorrelationId::new()))?
        .ok_or_else(refusal_error)?;
    let scope: DiscoveryScope = serde_json::from_str(&row.2).map_err(|_| corruption_error())?;
    let expected_revision =
        selection.source_revision_id().map(|id| id.as_uuid().as_bytes().to_vec());
    let expected_source_digest =
        selection.pinned_source_digest().map(|hash| hash.as_bytes().to_vec());
    if row.0.as_slice() != selection.verified_pack_digest().as_bytes().as_slice()
        || ContentHash::from_digest_bytes(&row.1) != selection.scope().digest().ok()
        || scope.canonical_bytes().ok() != selection.scope().canonical_bytes().ok()
        || row.3 != expected_revision
        || row.4 != expected_source_digest
        || row.5 != 0
        || require_current && row.6 != 1
    {
        return Err(refusal_error());
    }
    Ok(())
}

fn verify_run_selection(
    transaction: &Transaction<'_>,
    selection: &SelectionView,
    run: &RunRow,
    require_current: bool,
) -> Result<(), PortError> {
    if run.project_id != selection.project_id()
        || run.session_id != selection.runtime_session_id()
        || run.pack_digest != selection.verified_pack_digest()
        || run.protocol_minor != selection.protocol_minor()
        || run.owner_selection_id != *selection.owner_selection_id()
        || run.selection_epoch != selection.owner_selection_epoch()
        || run.namespace != selection.namespace().storage_key()
        || run.source_revision_id != selection.source_revision_id()
        || run.pinned_source_digest != selection.pinned_source_digest()
        || run.scope.canonical_bytes().ok() != selection.scope().canonical_bytes().ok()
    {
        return Err(conflict_error());
    }
    verify_selection(transaction, selection, require_current)
}

const DISCOVERY_RUN_TTL_SECONDS: i64 = 120;

fn expiry_from(started_at: &str) -> Result<String, PortError> {
    let started = OffsetDateTime::parse(started_at, &Rfc3339).map_err(|_| validation_error())?;
    started
        .checked_add(Duration::seconds(DISCOVERY_RUN_TTL_SECONDS))
        .ok_or_else(validation_error)?
        .format(&Rfc3339)
        .map_err(|_| validation_error())
}

fn stored_run_hint(namespace: CatalogRunNamespace, request_hint: &str) -> String {
    let digest = blake3::hash(request_hint.as_bytes());
    format!("{}:{}", namespace.storage_key(), digest.to_hex())
}

fn mark_expired(
    transaction: &Transaction<'_>,
    run_id: &[u8],
    now: &str,
    correlation_id: CorrelationId,
) -> Result<(), PortError> {
    transaction
        .execute(
            "UPDATE catalog_discovery_run_deadlines SET expired_at = ?2 WHERE run_id = ?1 AND expired_at IS NULL",
            params![run_id, now],
        )
        .map_err(|error| map_rusqlite(error, correlation_id))?;
    Ok(())
}

fn is_expired(started_at: &str, expires_at: &str, now: &str) -> Result<bool, PortError> {
    let started = OffsetDateTime::parse(started_at, &Rfc3339).map_err(|_| corruption_error())?;
    let expires = OffsetDateTime::parse(expires_at, &Rfc3339).map_err(|_| corruption_error())?;
    let current = OffsetDateTime::parse(now, &Rfc3339).map_err(|_| corruption_error())?;
    let expected_expiry = started
        .checked_add(Duration::seconds(DISCOVERY_RUN_TTL_SECONDS))
        .ok_or_else(corruption_error)?;
    if expires != expected_expiry {
        return Err(corruption_error());
    }
    if current < started {
        // A wall-clock rollback must never extend a persisted admission.
        return Err(conflict_error());
    }
    Ok(current >= expires)
}

fn provenance_matches_scope(provenance: ClaimProvenance, scope: &DiscoveryScope) -> bool {
    match scope.kind {
        DiscoveryScopeKind::StaticRepository => {
            matches!(provenance, ClaimProvenance::StaticInferred | ClaimProvenance::ImportedSpec)
        }
        DiscoveryScopeKind::RuntimeRegistration => provenance == ClaimProvenance::RuntimeDiscovered,
    }
}

fn load_run(transaction: &Transaction<'_>, run_id: RunId) -> Result<RunRow, PortError> {
    let row = transaction
        .query_row(
            "SELECT r.project_id, r.runtime_session_id, r.verified_pack_digest, r.protocol_minor, r.owner_selection_id, r.selection_epoch, r.scope_digest, r.scope_json, r.source_revision_id, r.pinned_source_digest, r.accepted_claim_count, r.accepted_claim_bytes, r.status, k.retry_namespace, d.started_at, d.expires_at, d.expired_at \
             FROM catalog_discovery_runs r LEFT JOIN catalog_discovery_retry_keys k ON k.run_id = r.run_id LEFT JOIN catalog_discovery_run_deadlines d ON d.run_id = r.run_id WHERE r.run_id = ?1",
            params![run_id.as_uuid().as_bytes().to_vec()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, i64>(3)?, row.get::<_, Vec<u8>>(4)?, row.get::<_, i64>(5)?, row.get::<_, Vec<u8>>(6)?, row.get::<_, String>(7)?, row.get::<_, Option<Vec<u8>>>(8)?, row.get::<_, Option<Vec<u8>>>(9)?, row.get::<_, i64>(10)?, row.get::<_, i64>(11)?, row.get::<_, String>(12)?, row.get::<_, Option<String>>(13)?, row.get::<_, Option<String>>(14)?, row.get::<_, Option<String>>(15)?, row.get::<_, Option<String>>(16)?)),
        )
        .optional()
        .map_err(|error| map_rusqlite(error, CorrelationId::new()))?
        .ok_or_else(|| PortError::new(PortErrorKind::NotFound, "catalog run was not found", CorrelationId::new()))?;
    let project_id = decode_id::<ProjectId>(&row.0).ok_or_else(corruption_error)?;
    let session_id =
        decode_id::<xtrace_domain::RuntimeSessionId>(&row.1).ok_or_else(corruption_error)?;
    let pack_digest = ContentHash::from_digest_bytes(&row.2).ok_or_else(corruption_error)?;
    let protocol_minor = u32::try_from(row.3).map_err(|_| corruption_error())?;
    let owner_selection_id: [u8; 16] = row.4.try_into().map_err(|_| corruption_error())?;
    let scope: DiscoveryScope = serde_json::from_str(&row.7).map_err(|_| corruption_error())?;
    let scope_digest = ContentHash::from_digest_bytes(&row.6).ok_or_else(corruption_error)?;
    if scope.digest().ok() != Some(scope_digest) {
        return Err(corruption_error());
    }
    let source_revision_id = match row.8.as_deref() {
        Some(bytes) => Some(decode_id::<SourceRevisionId>(bytes).ok_or_else(corruption_error)?),
        None => None,
    };
    let pinned_source_digest = match row.9.as_deref() {
        Some(bytes) => Some(ContentHash::from_digest_bytes(bytes).ok_or_else(corruption_error)?),
        None => None,
    };
    Ok(RunRow {
        project_id,
        session_id,
        pack_digest,
        protocol_minor,
        owner_selection_id,
        selection_epoch: u64::try_from(row.5).map_err(|_| corruption_error())?,
        namespace: row.13.unwrap_or_else(|| "legacy_unscoped".to_owned()),
        started_at: row.14,
        expires_at: row.15,
        expired_at: row.16,
        scope_digest,
        scope,
        source_revision_id,
        pinned_source_digest,
        accepted_claim_count: u32::try_from(row.10).map_err(|_| corruption_error())?,
        accepted_claim_bytes: u32::try_from(row.11).map_err(|_| corruption_error())?,
        status: row.12,
    })
}

fn load_and_verify_chunks(
    transaction: &Transaction<'_>,
    run_id: RunId,
    project_id: ProjectId,
    scope: &DiscoveryScope,
) -> Result<Vec<DiscoveryChunk>, PortError> {
    let mut chunk_statement = transaction
        .prepare("SELECT chunk_index, chunk_digest, claim_count FROM catalog_discovery_chunks WHERE run_id = ?1 AND project_id = ?2 ORDER BY chunk_index")
        .map_err(|error| map_rusqlite(error, CorrelationId::new()))?;
    let chunk_rows = chunk_statement
        .query_map(
            params![run_id.as_uuid().as_bytes().to_vec(), project_id.as_uuid().as_bytes().to_vec()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?)),
        )
        .map_err(|error| map_rusqlite(error, CorrelationId::new()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| map_rusqlite(error, CorrelationId::new()))?;
    if chunk_rows.len() > 64 {
        return Err(corruption_error());
    }
    let expected_claim_count = chunk_rows
        .iter()
        .try_fold(0_i64, |total, row| total.checked_add(row.2).ok_or_else(corruption_error))?;
    let expected_canonical_bytes: i64 = transaction
        .query_row(
            "SELECT COALESCE(SUM(payload_bytes), 0) FROM catalog_discovery_chunks WHERE run_id = ?1 AND project_id = ?2",
            params![run_id.as_uuid().as_bytes().to_vec(), project_id.as_uuid().as_bytes().to_vec()],
            |row| row.get(0),
        )
        .map_err(|error| map_rusqlite(error, CorrelationId::new()))?;
    let stored_claim_bounds: (i64, i64, i64, i64, i64) = transaction
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(canonical_bytes)), 0), \
                    COALESCE(SUM(length(CAST(canonical_json AS BLOB))), 0), \
                    COALESCE(MAX(length(canonical_bytes)), 0), \
                    COALESCE(MAX(length(CAST(canonical_json AS BLOB))), 0) \
             FROM catalog_discovery_claims WHERE run_id = ?1 AND project_id = ?2",
            params![run_id.as_uuid().as_bytes().to_vec(), project_id.as_uuid().as_bytes().to_vec()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .map_err(|error| map_rusqlite(error, CorrelationId::new()))?;
    if expected_claim_count > 4096
        || expected_canonical_bytes > 4 * 1024 * 1024
        || stored_claim_bounds.0 != expected_claim_count
        || stored_claim_bounds.1 != expected_canonical_bytes
        || stored_claim_bounds.1 > 4 * 1024 * 1024
        || stored_claim_bounds.2 > 64 * 1024 * 1024
        || stored_claim_bounds.3 > 8192
        || stored_claim_bounds.4 > 16 * 1024
    {
        return Err(corruption_error());
    }
    let mut chunks = Vec::with_capacity(chunk_rows.len());
    for (expected_index, (index, stored_digest, stored_count)) in chunk_rows.into_iter().enumerate()
    {
        if usize::try_from(index).ok() != Some(expected_index) {
            return Err(validation_error());
        }
        let mut claim_statement = transaction
            .prepare("SELECT claim_digest, canonical_bytes, canonical_json FROM catalog_discovery_claims WHERE run_id = ?1 AND project_id = ?2 AND chunk_index = ?3 ORDER BY claim_ordinal")
            .map_err(|error| map_rusqlite(error, CorrelationId::new()))?;
        let claim_rows = claim_statement
            .query_map(
                params![
                    run_id.as_uuid().as_bytes().to_vec(),
                    project_id.as_uuid().as_bytes().to_vec(),
                    index
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .map_err(|error| map_rusqlite(error, CorrelationId::new()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| map_rusqlite(error, CorrelationId::new()))?;
        if claim_rows.len() != usize::try_from(stored_count).map_err(|_| corruption_error())? {
            return Err(corruption_error());
        }
        let mut claims = Vec::with_capacity(claim_rows.len());
        for (digest_bytes, canonical, json) in claim_rows {
            let stored: StoredClaim =
                serde_json::from_str(&json).map_err(|_| corruption_error())?;
            let claim = stored.rebuild().map_err(|_| corruption_error())?;
            if claim.canonical_bytes() != canonical
                || claim.digest().map(|hash| hash.as_bytes().to_vec()) != Some(digest_bytes)
                || claim.operation().application_component != scope.application_component
                || claim.operation().binding_key != scope.binding_key
                || !provenance_matches_scope(claim.provenance(), scope)
            {
                return Err(corruption_error());
            }
            claims.push(claim);
        }
        let chunk = DiscoveryChunk {
            run_id,
            chunk_index: u32::try_from(index).map_err(|_| corruption_error())?,
            claims,
        };
        if chunk.digest().ok().map(|hash| hash.as_bytes().to_vec()) != Some(stored_digest) {
            return Err(corruption_error());
        }
        chunks.push(chunk);
    }
    Ok(chunks)
}

fn publish_revision(
    transaction: &Transaction<'_>,
    selection: &SelectionView,
    run: &RunRow,
    finish: &DiscoveryRunFinish,
    chunks: &[DiscoveryChunk],
    limitation_json: &str,
    correlation_id: CorrelationId,
) -> Result<(), PortError> {
    let revision_id = CatalogRevisionId::new();
    let prior = transaction
        .query_row(
            "SELECT revision_id, ordinal FROM catalog_revisions WHERE project_id = ?1 AND scope_digest = ?2 ORDER BY ordinal DESC LIMIT 1",
            params![selection.project_id().as_uuid().as_bytes().to_vec(), run.scope_digest.as_bytes().to_vec()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|error| map_rusqlite(error, correlation_id))?;
    let parent_revision = prior
        .as_ref()
        .map(|row| decode_id::<CatalogRevisionId>(&row.0).ok_or_else(corruption_error))
        .transpose()?;
    let ordinal = prior.as_ref().map_or(1_i64, |row| row.1.saturating_add(1));
    let mut grouped: BTreeMap<
        Vec<u8>,
        Vec<&xtrace_domain::catalog_discovery::ValidatedEndpointClaim>,
    > = BTreeMap::new();
    for chunk in chunks {
        for claim in &chunk.claims {
            let fingerprint = claim.operation().fingerprint().map_err(|_| validation_error())?;
            grouped.entry(fingerprint.as_bytes().to_vec()).or_default().push(claim);
        }
    }
    let mut operation_rows = Vec::with_capacity(grouped.len());
    let mut content = blake3::Hasher::new();
    content.update(b"xtrace.catalog-content.v1\0");
    for (fingerprint, claims) in grouped {
        let operation = claims.first().ok_or_else(corruption_error)?.operation();
        let operation_id =
            find_or_create_operation(transaction, operation, &fingerprint, correlation_id)?;
        let mut claim_digests: Vec<[u8; 32]> = claims
            .iter()
            .map(|claim| {
                claim.digest().map(|digest| *digest.as_bytes()).ok_or_else(corruption_error)
            })
            .collect::<Result<_, _>>()?;
        claim_digests.sort_unstable();
        let mut version_hasher = blake3::Hasher::new();
        version_hasher.update(b"xtrace.operation-version.v1\0");
        version_hasher.update(&fingerprint);
        for digest in &claim_digests {
            version_hasher.update(digest);
        }
        let version_digest = *version_hasher.finalize().as_bytes();
        let lifecycle = if claims
            .iter()
            .any(|claim| claim.provenance() == ClaimProvenance::RuntimeDiscovered)
        {
            "registered"
        } else {
            "inferred"
        };
        let operation_version_id = find_or_create_version(
            transaction,
            selection.project_id(),
            operation_id,
            &version_digest,
            lifecycle,
            correlation_id,
        )?;
        content.update(&fingerprint);
        content.update(&version_digest);
        operation_rows.push((operation_id, operation_version_id, fingerprint, claims));
    }
    let content_digest = *content.finalize().as_bytes();
    transaction.execute(
        "INSERT INTO catalog_revisions (revision_id, project_id, owner_selection_id, run_id, scope_digest, source_revision_id, ordinal, parent_revision_id, content_digest, final_digest, operation_count, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        params![revision_id.as_uuid().as_bytes().to_vec(), selection.project_id().as_uuid().as_bytes().to_vec(), selection.owner_selection_id().to_vec(), finish.run_id.as_uuid().as_bytes().to_vec(), run.scope_digest.as_bytes().to_vec(), run.source_revision_id.map(|id| id.as_uuid().as_bytes().to_vec()), ordinal, parent_revision.map(|id| id.as_uuid().as_bytes().to_vec()), content_digest.to_vec(), finish.final_digest.as_bytes().to_vec(), i64::try_from(operation_rows.len()).map_err(|_| validation_error())?],
    ).map_err(|error| map_rusqlite(error, correlation_id))?;
    for (operation_id, version_id, _fingerprint, claims) in operation_rows {
        let kind = prior_change_kind(
            transaction,
            parent_revision,
            operation_id,
            version_id,
            correlation_id,
        )?;
        transaction.execute(
            "INSERT INTO catalog_revision_entries (project_id, revision_id, operation_id, operation_version_id, change_kind, source_availability) VALUES (?1, ?2, ?3, ?4, ?5, 'unverified')",
            params![selection.project_id().as_uuid().as_bytes().to_vec(), revision_id.as_uuid().as_bytes().to_vec(), operation_id.as_uuid().as_bytes().to_vec(), version_id.as_uuid().as_bytes().to_vec(), kind],
        ).map_err(|error| map_rusqlite(error, correlation_id))?;
        for claim in claims {
            let claim_id = find_or_create_claim(
                transaction,
                selection.project_id(),
                operation_id,
                revision_id,
                claim,
                correlation_id,
            )?;
            transaction.execute(
                "INSERT INTO catalog_revision_claims (project_id, revision_id, operation_id, claim_id) VALUES (?1, ?2, ?3, ?4)",
                params![selection.project_id().as_uuid().as_bytes().to_vec(), revision_id.as_uuid().as_bytes().to_vec(), operation_id.as_uuid().as_bytes().to_vec(), claim_id.as_uuid().as_bytes().to_vec()],
            ).map_err(|error| map_rusqlite(error, correlation_id))?;
        }
    }
    // Missing prior entries stay explicitly unknown until a trusted scope
    // inventory can prove that no current selection or observed recording
    // sustains them. Never turn absence in one transcript into deletion.
    if let Some(parent_id) = parent_revision {
        let mut statement = transaction.prepare(
            "SELECT operation_id, operation_version_id FROM catalog_revision_entries WHERE revision_id = ?1 ORDER BY operation_id",
        ).map_err(|error| map_rusqlite(error, correlation_id))?;
        let previous = statement
            .query_map(params![parent_id.as_uuid().as_bytes().to_vec()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|error| map_rusqlite(error, correlation_id))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        for (operation_bytes, version_bytes) in previous {
            let operation_id =
                decode_id::<OperationId>(&operation_bytes).ok_or_else(corruption_error)?;
            let present: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM catalog_revision_entries WHERE revision_id = ?1 AND operation_id = ?2)",
                params![revision_id.as_uuid().as_bytes().to_vec(), operation_bytes], |row| row.get(0),
            ).map_err(|error| map_rusqlite(error, correlation_id))?;
            if !present {
                let version_id =
                    decode_id::<OperationVersionId>(&version_bytes).ok_or_else(corruption_error)?;
                transaction.execute(
                    "INSERT INTO catalog_revision_entries (project_id, revision_id, operation_id, operation_version_id, change_kind, source_availability) VALUES (?1, ?2, ?3, ?4, 'unknown', 'unavailable')",
                    params![selection.project_id().as_uuid().as_bytes().to_vec(), revision_id.as_uuid().as_bytes().to_vec(), operation_id.as_uuid().as_bytes().to_vec(), version_id.as_uuid().as_bytes().to_vec()],
                ).map_err(|error| map_rusqlite(error, correlation_id))?;
            }
        }
    }
    let final_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM catalog_revision_entries WHERE revision_id = ?1",
            params![revision_id.as_uuid().as_bytes().to_vec()],
            |row| row.get(0),
        )
        .map_err(|error| map_rusqlite(error, correlation_id))?;
    transaction
        .execute(
            "UPDATE catalog_revisions SET operation_count = ?2 WHERE revision_id = ?1",
            params![revision_id.as_uuid().as_bytes().to_vec(), final_count],
        )
        .map_err(|error| map_rusqlite(error, correlation_id))?;
    transaction.execute(
        "UPDATE catalog_discovery_runs SET status = 'complete', expected_chunk_count = ?2, rejected_claim_count = ?3, final_digest = ?4, limitation_codes_json = ?5, revision_id = ?6 WHERE run_id = ?1 AND status = 'open'",
        params![finish.run_id.as_uuid().as_bytes().to_vec(), i64::from(finish.expected_chunk_count), i64::from(finish.rejected_claim_count), finish.final_digest.as_bytes().to_vec(), limitation_json, revision_id.as_uuid().as_bytes().to_vec()],
    ).map_err(|error| map_rusqlite(error, correlation_id))?;
    Ok(())
}

fn find_or_create_operation(
    transaction: &Transaction<'_>,
    identity: &EndpointIdentity,
    fingerprint: &[u8],
    correlation_id: CorrelationId,
) -> Result<OperationId, PortError> {
    let tuple = (
        identity.application_component.as_str(),
        identity.binding_key.as_str(),
        identity.transport.as_str(),
        identity.method.as_str(),
        identity.route_template.as_str(),
    );
    let current = transaction.query_row(
        "SELECT operation_id, application_component, binding_key, transport, method, route_template FROM catalog_operations WHERE project_id = ?1 AND fingerprint_format = 1 AND endpoint_fingerprint = ?2",
        params![identity.project_id.as_uuid().as_bytes().to_vec(), fingerprint],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?)),
    ).optional().map_err(|error| map_rusqlite(error, correlation_id))?;
    if let Some(row) = current {
        if (row.1.as_str(), row.2.as_str(), row.3.as_str(), row.4.as_str(), row.5.as_str()) != tuple
        {
            return Err(corruption_error());
        }
        return decode_id::<OperationId>(&row.0).ok_or_else(corruption_error);
    }
    // Preserve the finite v0003 /orders identity when that row already exists.
    let legacy = transaction.query_row(
        "SELECT operation_id, application_component, binding_key, transport, method, route_template FROM operations \
         WHERE project_id = ?1 AND fingerprint_format_version = 1 AND endpoint_fingerprint = ?2",
        params![identity.project_id.as_uuid().as_bytes().to_vec(), fingerprint],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?)),
    ).optional().map_err(|error| map_rusqlite(error, correlation_id))?;
    let legacy_existed = legacy.is_some();
    let (operation_id, component, binding, transport, method, route) = match legacy {
        Some(row) => row,
        None => (
            OperationId::new().as_uuid().as_bytes().to_vec(),
            tuple.0.to_owned(),
            tuple.1.to_owned(),
            tuple.2.to_owned(),
            tuple.3.to_owned(),
            tuple.4.to_owned(),
        ),
    };
    if (component.as_str(), binding.as_str(), transport.as_str(), method.as_str(), route.as_str())
        != tuple
    {
        return Err(corruption_error());
    }
    transaction.execute(
        "INSERT INTO catalog_operations (operation_id, project_id, fingerprint_format, endpoint_fingerprint, transport, application_component, binding_key, method, route_template, created_at) VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        params![operation_id, identity.project_id.as_uuid().as_bytes().to_vec(), fingerprint, tuple.2, tuple.0, tuple.1, tuple.3, tuple.4],
    ).map_err(|error| map_rusqlite(error, correlation_id))?;
    if !legacy_existed && tuple == ("spring-fixture", "default", "http", "POST", "/orders") {
        transaction.execute(
            "INSERT INTO operations (operation_id, project_id, transport, method, route_template, application_component, binding_key, fingerprint_format_version, endpoint_fingerprint, created_at) \
             VALUES (?1, ?2, 'http', 'POST', '/orders', 'spring-fixture', 'default', 1, ?3, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
            params![operation_id, identity.project_id.as_uuid().as_bytes().to_vec(), fingerprint],
        ).map_err(|error| map_rusqlite(error, correlation_id))?;
    }
    decode_id::<OperationId>(&operation_id).ok_or_else(corruption_error)
}

fn find_or_create_version(
    transaction: &Transaction<'_>,
    project_id: ProjectId,
    operation_id: OperationId,
    digest: &[u8; 32],
    lifecycle: &str,
    correlation_id: CorrelationId,
) -> Result<OperationVersionId, PortError> {
    if let Some(bytes) = transaction.query_row(
        "SELECT operation_version_id FROM catalog_operation_versions WHERE project_id = ?1 AND operation_id = ?2 AND version_digest = ?3",
        params![project_id.as_uuid().as_bytes().to_vec(), operation_id.as_uuid().as_bytes().to_vec(), digest.as_slice()],
        |row| row.get::<_, Vec<u8>>(0),
    ).optional().map_err(|error| map_rusqlite(error, correlation_id))? {
        return decode_id::<OperationVersionId>(&bytes).ok_or_else(corruption_error);
    }
    let version_id = OperationVersionId::new();
    transaction.execute(
        "INSERT INTO catalog_operation_versions (operation_version_id, project_id, operation_id, version_digest, lifecycle, created_at) VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        params![version_id.as_uuid().as_bytes().to_vec(), project_id.as_uuid().as_bytes().to_vec(), operation_id.as_uuid().as_bytes().to_vec(), digest.as_slice(), lifecycle],
    ).map_err(|error| map_rusqlite(error, correlation_id))?;
    Ok(version_id)
}

fn find_or_create_claim(
    transaction: &Transaction<'_>,
    project_id: ProjectId,
    operation_id: OperationId,
    revision_id: CatalogRevisionId,
    claim: &xtrace_domain::catalog_discovery::ValidatedEndpointClaim,
    correlation_id: CorrelationId,
) -> Result<ClaimId, PortError> {
    let digest = claim.digest().ok_or_else(corruption_error)?;
    let json =
        serde_json::to_string(&StoredClaim::from_claim(claim)).map_err(|_| validation_error())?;
    if let Some(row) = transaction.query_row(
        "SELECT claim_id, operation_id, canonical_bytes, canonical_json FROM catalog_claims WHERE project_id = ?1 AND claim_digest = ?2",
        params![project_id.as_uuid().as_bytes().to_vec(), digest.as_bytes().to_vec()],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, String>(3)?)),
    ).optional().map_err(|error| map_rusqlite(error, correlation_id))? {
        if row.1 != operation_id.as_uuid().as_bytes()
            || row.2 != claim.canonical_bytes()
            || row.3 != json
        { return Err(corruption_error()); }
        let claim_id = decode_id::<ClaimId>(&row.0).ok_or_else(corruption_error)?;
        transaction.execute(
            "UPDATE catalog_claims SET last_revision_id = ?2 WHERE project_id = ?1 AND claim_id = ?3",
            params![project_id.as_uuid().as_bytes().to_vec(), revision_id.as_uuid().as_bytes().to_vec(), claim_id.as_uuid().as_bytes().to_vec()],
        ).map_err(|error| map_rusqlite(error, correlation_id))?;
        return Ok(claim_id);
    }
    let claim_id = ClaimId::new();
    transaction.execute(
        "INSERT INTO catalog_claims (claim_id, project_id, operation_id, claim_digest, canonical_bytes, canonical_json, first_revision_id, last_revision_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
        params![claim_id.as_uuid().as_bytes().to_vec(), project_id.as_uuid().as_bytes().to_vec(), operation_id.as_uuid().as_bytes().to_vec(), digest.as_bytes().to_vec(), claim.canonical_bytes(), json, revision_id.as_uuid().as_bytes().to_vec()],
    ).map_err(|error| map_rusqlite(error, correlation_id))?;
    Ok(claim_id)
}

fn prior_change_kind(
    transaction: &Transaction<'_>,
    parent: Option<CatalogRevisionId>,
    operation_id: OperationId,
    version_id: OperationVersionId,
    correlation_id: CorrelationId,
) -> Result<&'static str, PortError> {
    let Some(parent) = parent else {
        return Ok("added");
    };
    let previous = transaction.query_row(
        "SELECT operation_version_id FROM catalog_revision_entries WHERE revision_id = ?1 AND operation_id = ?2",
        params![parent.as_uuid().as_bytes().to_vec(), operation_id.as_uuid().as_bytes().to_vec()],
        |row| row.get::<_, Vec<u8>>(0),
    ).optional().map_err(|error| map_rusqlite(error, correlation_id))?;
    match previous {
        None => Ok("added"),
        Some(bytes) if bytes == version_id.as_uuid().as_bytes() => Ok("unchanged"),
        Some(_) => Ok("changed"),
    }
}

fn decode_id<T: From<uuid::Uuid>>(bytes: &[u8]) -> Option<T> {
    let uuid = uuid::Uuid::from_slice(bytes).ok()?;
    if uuid.get_version_num() != 7 || uuid.get_variant() != uuid::Variant::RFC4122 {
        return None;
    }
    Some(T::from(uuid))
}

fn map_store_error(error: StoreError) -> PortError {
    map_store_kind(error.kind(), error.message(), error.correlation_id())
}

fn map_rusqlite(error: rusqlite::Error, correlation_id: CorrelationId) -> PortError {
    map_store_error(StoreError::from_rusqlite(error, correlation_id))
}

fn map_store_kind(kind: StoreErrorKind, message: &str, correlation_id: CorrelationId) -> PortError {
    let mapped = match kind {
        StoreErrorKind::Validation => PortErrorKind::Validation,
        StoreErrorKind::AlreadyExists => PortErrorKind::AlreadyExists,
        StoreErrorKind::NotFound => PortErrorKind::NotFound,
        StoreErrorKind::Conflict => PortErrorKind::Conflict,
        StoreErrorKind::SchemaOlder
        | StoreErrorKind::SchemaNewer
        | StoreErrorKind::SchemaIncompatible => PortErrorKind::Compatibility,
        StoreErrorKind::Busy | StoreErrorKind::Resource | StoreErrorKind::Permission => {
            PortErrorKind::Resource
        }
        StoreErrorKind::Corruption => PortErrorKind::Corruption,
        StoreErrorKind::Transport => PortErrorKind::Transport,
        StoreErrorKind::Internal => PortErrorKind::Internal,
    };
    PortError::new(mapped, message, correlation_id)
}

fn validation_error() -> PortError {
    PortError::new(PortErrorKind::Validation, "catalog proof is invalid", CorrelationId::new())
}

fn conflict_error() -> PortError {
    PortError::new(
        PortErrorKind::Conflict,
        "catalog discovery conflicts with durable history",
        CorrelationId::new(),
    )
}

fn corruption_error() -> PortError {
    PortError::new(
        PortErrorKind::Corruption,
        "catalog discovery evidence is inconsistent",
        CorrelationId::new(),
    )
}

fn refusal_error() -> PortError {
    PortError::new(
        PortErrorKind::Conflict,
        "catalog authority is unavailable or revoked",
        CorrelationId::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::connection::{OpenOptions, SqliteStore};
    use std::{env, fs, path::PathBuf};

    #[test]
    fn test_clock_and_persisted_deadline_enforce_exact_ttl_and_clock_rollback() {
        let shared = SqliteStore::open_in_memory(OpenOptions::default()).expect("store");
        let store = SqliteCatalogDiscoveryStore::new(shared);
        store.set_test_now("2026-10-04T00:00:00Z");
        assert_eq!(store.now(), "2026-10-04T00:00:00Z");
        let started = store.now();
        let expires = expiry_from(&started).expect("checked deadline");
        let expected = OffsetDateTime::parse("2026-10-04T00:02:00Z", &Rfc3339).expect("time");
        assert_eq!(OffsetDateTime::parse(&expires, &Rfc3339).expect("expiry"), expected);
        assert!(!is_expired(&started, &expires, "2026-10-04T00:01:59Z").expect("before deadline"));
        assert!(is_expired(&started, &expires, &expires).expect("at deadline"));
        assert!(is_expired(&started, &expires, "2026-10-03T23:59:59Z").is_err());
        assert!(is_expired(&started, "2026-10-04T00:02:01Z", "2026-10-04T00:01:00Z").is_err());
        assert!(expiry_from("9999-12-31T23:59:59Z").is_err());
    }

    fn test_scope(component: &str) -> DiscoveryScope {
        DiscoveryScope {
            kind: DiscoveryScopeKind::RuntimeRegistration,
            source_root_key: None,
            module_selector: "test-module".to_owned(),
            application_component: component.to_owned(),
            binding_key: "default".to_owned(),
            framework_family: "fixture".to_owned(),
            producer_family: "fixture".to_owned(),
            ruleset_digest: ContentHash::of_bytes(b"test-rules"),
        }
    }

    fn test_selection(scope: DiscoveryScope, namespace: CatalogRunNamespace) -> SelectionView {
        SelectionView {
            project_id: ProjectId::new(),
            runtime_session_id: xtrace_domain::RuntimeSessionId::new(),
            verified_pack_digest: ContentHash::of_bytes(b"test-pack"),
            protocol_minor: 1,
            namespace,
            owner_selection_id: *uuid::Uuid::now_v7().as_bytes(),
            owner_selection_epoch: 1,
            scope,
            source_revision_id: None,
            pinned_source_digest: None,
        }
    }

    fn seed_authority(store: &SqliteStore, selection: &SelectionView) {
        let connection = store.lock().expect("database connection");
        connection.execute(
            "INSERT INTO projects (project_id, canonical_repo_hash, display_name, created_at, last_opened_at, config_schema_version, effective_config_hash) VALUES (?1, ?2, 'fixture', '2026-10-04T00:00:00Z', '2026-10-04T00:00:00Z', 1, ?3)",
            params![selection.project_id().as_uuid().as_bytes().to_vec(), format!("b3:{}", "0".repeat(64)), "0".repeat(64)],
        ).expect("seed project");
        connection.execute(
            "INSERT INTO catalog_owner_selections (owner_selection_id, project_id, selection_epoch, current_for_scope, verified_pack_digest, scope_digest, scope_json, revoked) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, 0)",
            params![selection.owner_selection_id().to_vec(), selection.project_id().as_uuid().as_bytes().to_vec(), i64::try_from(selection.owner_selection_epoch()).expect("epoch"), selection.verified_pack_digest().as_bytes().to_vec(), selection.scope().digest().expect("scope digest").as_bytes().to_vec(), serde_json::to_string(selection.scope()).expect("scope JSON")],
        ).expect("seed owner selection");
    }

    fn private_database(label: &str) -> (PathBuf, PathBuf) {
        let scratch = env::var_os("XTRACE_TEST_PRIVATE_SCRATCH")
            .map(PathBuf::from)
            .expect("XTRACE_TEST_PRIVATE_SCRATCH must point to private test storage");
        fs::create_dir_all(&scratch).expect("create private test scratch");
        let root = scratch.join(format!("catalog-store-{label}-{}", uuid::Uuid::now_v7().simple()));
        fs::create_dir(&root).expect("create isolated catalog test directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("restrict test directory");
        }
        let database = root.join("catalog.sqlite3");
        (root, database)
    }

    fn start_request(scope: &DiscoveryScope, hint: &str) -> DiscoveryRunStartRequest {
        DiscoveryRunStartRequest {
            schema_version: 1,
            run_hint: hint.to_owned(),
            requested_scope: scope.clone(),
            owner_selection_ref: Some("test-owner".to_owned()),
        }
    }

    #[allow(clippy::panic, reason = "test helper asserts the grant was admitted")]
    fn run_id(grant: DiscoveryRunGrant) -> RunId {
        match grant {
            DiscoveryRunGrant::Admitted { run_id, .. } => run_id,
            DiscoveryRunGrant::Refused { .. } => panic!("test run unexpectedly refused"),
        }
    }

    fn test_claim(
        project_id: ProjectId,
        component: &str,
        hint: &str,
    ) -> xtrace_domain::catalog_discovery::ValidatedEndpointClaim {
        let identity = EndpointIdentity {
            project_id,
            application_component: component.to_owned(),
            transport: Transport::Http,
            binding_key: "default".to_owned(),
            method: HttpMethod::Post,
            route_template: "/orders".to_owned(),
        };
        xtrace_domain::catalog_discovery::ValidatedEndpointClaim::new(
            hint.to_owned(),
            identity,
            ClaimProvenance::RuntimeDiscovered,
            None,
            -1.0,
            Vec::new(),
            Vec::new(),
        )
        .expect("valid scoped claim")
    }

    fn test_finish(
        run_id: RunId,
        scope: &DiscoveryScope,
        chunks: &[DiscoveryChunk],
    ) -> DiscoveryRunFinish {
        let accepted_claim_count = chunks.iter().map(|chunk| chunk.claims.len() as u32).sum();
        DiscoveryRunFinish {
            run_id,
            expected_chunk_count: chunks.len() as u32,
            accepted_claim_count,
            rejected_claim_count: 0,
            final_digest: xtrace_domain::catalog_discovery::final_digest(
                run_id,
                scope,
                None,
                chunks,
                0,
                DiscoveryCompletion::Complete,
            )
            .expect("final digest"),
            completion: DiscoveryCompletion::Complete,
            limitation_codes: Vec::new(),
        }
    }

    fn insert_project(store: &SqliteStore, project_id: ProjectId) {
        let connection = store.lock().expect("database connection");
        connection.execute(
            "INSERT INTO projects (project_id, canonical_repo_hash, display_name, created_at, last_opened_at, config_schema_version, effective_config_hash) VALUES (?1, ?2, 'fixture', '2026-10-04T00:00:00Z', '2026-10-04T00:00:00Z', 1, ?3)",
            params![project_id.as_uuid().as_bytes().to_vec(), format!("b3:{}", "0".repeat(64)), "0".repeat(64)],
        ).expect("seed project");
    }

    fn static_scope(component: &str) -> DiscoveryScope {
        DiscoveryScope {
            kind: DiscoveryScopeKind::StaticRepository,
            source_root_key: Some("src-test".to_owned()),
            module_selector: "default".to_owned(),
            application_component: component.to_owned(),
            binding_key: "default".to_owned(),
            framework_family: "express".to_owned(),
            producer_family: "local-static-scan".to_owned(),
            ruleset_digest: ContentHash::of_bytes(b"test-rules"),
        }
    }

    fn static_claim(
        project_id: ProjectId,
        component: &str,
        revision: SourceRevisionId,
        digest: ContentHash,
    ) -> xtrace_domain::catalog_discovery::ValidatedEndpointClaim {
        let identity = EndpointIdentity {
            project_id,
            application_component: component.to_owned(),
            transport: Transport::Http,
            binding_key: "default".to_owned(),
            method: HttpMethod::Get,
            route_template: "/orders".to_owned(),
        };
        xtrace_domain::catalog_discovery::ValidatedEndpointClaim::new(
            "st-1".to_owned(),
            identity,
            ClaimProvenance::StaticInferred,
            None,
            0.9,
            Vec::new(),
            vec![ClaimSourceEvidence::StaticSnapshot {
                source_revision_id: revision,
                relative_path: "routes.js".to_owned(),
                recorded_source_digest: digest,
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 2,
            }],
        )
        .expect("valid static claim")
    }

    fn row_count(store: &SqliteStore, table: &str) -> i64 {
        store
            .lock()
            .expect("database connection")
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
            .expect("count rows")
    }

    #[test]
    fn store_refuses_a_static_claim_citing_a_snapshot_the_selection_did_not_pin() {
        let shared = SqliteStore::open_in_memory(OpenOptions::default()).expect("store");
        let scope = static_scope("orders");
        let pinned = SourceRevisionId::new();
        let mut selection = test_selection(scope.clone(), CatalogRunNamespace::LocalStaticScanner);
        selection.source_revision_id = Some(pinned);
        selection.pinned_source_digest = Some(ContentHash::of_bytes(b"snapshot"));
        insert_project(&shared, selection.project_id());
        shared.lock().expect("connection").execute(
            "INSERT INTO catalog_owner_selections (owner_selection_id, project_id, selection_epoch, current_for_scope, verified_pack_digest, scope_digest, scope_json, source_revision_id, pinned_source_digest, revoked) VALUES (?1, ?2, 1, 1, ?3, ?4, ?5, ?6, ?7, 0)",
            params![selection.owner_selection_id().to_vec(), selection.project_id().as_uuid().as_bytes().to_vec(), selection.verified_pack_digest().as_bytes().to_vec(), scope.digest().expect("digest").as_bytes().to_vec(), serde_json::to_string(&scope).expect("scope JSON"), pinned.as_uuid().as_bytes().to_vec(), ContentHash::of_bytes(b"snapshot").as_bytes().to_vec()],
        ).expect("seed pinned selection");

        let adapter = SqliteCatalogDiscoveryStore::new(shared.clone());
        let run = run_id(
            adapter.start_run_with_view(&selection, &start_request(&scope, "pin")).expect("start"),
        );
        let digest = ContentHash::of_bytes(b"routes");
        let chunk = |revision| DiscoveryChunk {
            run_id: run,
            chunk_index: 0,
            claims: vec![static_claim(selection.project_id(), "orders", revision, digest)],
        };
        let error = adapter
            .submit_chunk_with_view(&selection, &chunk(SourceRevisionId::new()))
            .expect_err("wrong snapshot is refused");
        assert_eq!(error.kind, PortErrorKind::Conflict);
        assert_eq!(row_count(&shared, "catalog_discovery_claims"), 0);
        adapter.submit_chunk_with_view(&selection, &chunk(pinned)).expect("pinned snapshot");
        assert_eq!(row_count(&shared, "catalog_discovery_claims"), 1);
    }

    #[test]
    fn store_refuses_a_class_bound_claim_in_the_local_scan_namespace() {
        let shared = SqliteStore::open_in_memory(OpenOptions::default()).expect("store");
        let scope = static_scope("orders");
        let selection = test_selection(scope.clone(), CatalogRunNamespace::LocalStaticScanner);
        insert_project(&shared, selection.project_id());
        shared.lock().expect("connection").execute(
            "INSERT INTO catalog_owner_selections (owner_selection_id, project_id, selection_epoch, current_for_scope, verified_pack_digest, scope_digest, scope_json, revoked) VALUES (?1, ?2, 1, 1, ?3, ?4, ?5, 0)",
            params![selection.owner_selection_id().to_vec(), selection.project_id().as_uuid().as_bytes().to_vec(), selection.verified_pack_digest().as_bytes().to_vec(), scope.digest().expect("digest").as_bytes().to_vec(), serde_json::to_string(&scope).expect("scope JSON")],
        ).expect("seed selection");
        let adapter = SqliteCatalogDiscoveryStore::new(shared.clone());
        let run = run_id(
            adapter.start_run_with_view(&selection, &start_request(&scope, "cls")).expect("start"),
        );
        let identity = EndpointIdentity {
            project_id: selection.project_id(),
            application_component: "orders".to_owned(),
            transport: Transport::Http,
            binding_key: "default".to_owned(),
            method: HttpMethod::Get,
            route_template: "/orders".to_owned(),
        };
        let claim = xtrace_domain::catalog_discovery::ValidatedEndpointClaim::new(
            "cl-1".to_owned(),
            identity,
            ClaimProvenance::StaticInferred,
            None,
            0.9,
            Vec::new(),
            vec![ClaimSourceEvidence::LoadedClassBound {
                loaded_class_digest: ContentHash::of_bytes(b"class"),
                relative_path: "routes.js".to_owned(),
                recorded_source_digest: ContentHash::of_bytes(b"routes"),
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 2,
            }],
        )
        .expect("valid class-bound claim");
        let chunk = DiscoveryChunk { run_id: run, chunk_index: 0, claims: vec![claim] };
        let error = adapter
            .submit_chunk_with_view(&selection, &chunk)
            .expect_err("class-bound claim is refused in the local-scan namespace");
        assert_eq!(error.kind, PortErrorKind::Conflict);
        assert_eq!(row_count(&shared, "catalog_discovery_claims"), 0);
    }

    struct FixedReader(Option<ContentHash>);
    impl xtrace_application::catalog_discovery::admission::SourceSnapshotReader for FixedReader {
        fn digest(&self, _relative_path: &str) -> Option<ContentHash> {
            self.0
        }
    }

    #[test]
    fn only_a_verified_local_scan_chunk_reaches_the_real_store() {
        use crate::catalog_admission_store::SqliteCatalogAdmissionStore;
        use xtrace_application::catalog_discovery::admission::{
            LocalScanAuthority, LocalScanSelection,
        };
        use xtrace_application::{
            CatalogDiscoveryError, CatalogDiscoveryService, CatalogProducerContext,
        };

        let shared = SqliteStore::open_in_memory(OpenOptions::default()).expect("store");
        let project_id = ProjectId::new();
        insert_project(&shared, project_id);
        let adapter = Arc::new(SqliteCatalogDiscoveryStore::new(shared.clone()));
        let scope = static_scope("orders");
        let recorded = ContentHash::of_bytes(b"routes");

        // The default service has fail-closed admission: it cannot even start a run, so a static
        // claim has no way to reach the store.
        let default_service = CatalogDiscoveryService::new(adapter.clone());
        let context = CatalogProducerContext {
            project_id,
            runtime_session_id: xtrace_domain::RuntimeSessionId::new(),
            verified_pack_digest: ContentHash::of_bytes(b"pack"),
            protocol_minor: 1,
            scoped_discovery_negotiated: true,
            namespace: CatalogRunNamespace::LocalStaticScanner,
        };
        let request = start_request(&scope, "scan-1");
        assert!(matches!(
            default_service.start_run(context, &request),
            Err(CatalogDiscoveryError::Refused(_))
        ));
        let forged = DiscoveryChunk {
            run_id: RunId::new(),
            chunk_index: 0,
            claims: vec![static_claim(project_id, "orders", SourceRevisionId::new(), recorded)],
        };
        assert!(matches!(
            default_service.submit_chunk(context, &forged),
            Err(CatalogDiscoveryError::Refused(_))
        ));
        assert_eq!(row_count(&shared, "catalog_discovery_runs"), 0);
        assert_eq!(row_count(&shared, "catalog_discovery_claims"), 0);

        // A local scan whose cited file changed since analysis is refused with zero rows.
        let revision = SourceRevisionId::new();
        let selection = LocalScanSelection {
            project_id,
            scope: scope.clone(),
            analyzer_digest: ContentHash::of_bytes(b"analyzer"),
            source_revision_id: revision,
            pinned_source_digest: ContentHash::of_bytes(b"snapshot"),
        };
        let admission = SqliteCatalogAdmissionStore::new(shared.clone());
        let stale = LocalScanAuthority::establish(
            &admission,
            &selection,
            Arc::new(FixedReader(Some(ContentHash::of_bytes(b"edited")))),
        )
        .expect("establish");
        let service = CatalogDiscoveryService::for_local_scan(adapter.clone(), &stale);
        let run = run_id(service.start_run(stale.context(), &request).expect("start"));
        let chunk = DiscoveryChunk {
            run_id: run,
            chunk_index: 0,
            claims: vec![static_claim(project_id, "orders", revision, recorded)],
        };
        assert!(matches!(
            service.submit_chunk(stale.context(), &chunk),
            Err(CatalogDiscoveryError::Refused(_))
        ));
        assert_eq!(row_count(&shared, "catalog_discovery_claims"), 0);

        // A fresh authority whose reader still sees the recorded bytes persists the chunk.
        let clean = LocalScanAuthority::establish(
            &admission,
            &selection,
            Arc::new(FixedReader(Some(recorded))),
        )
        .expect("establish");
        let service = CatalogDiscoveryService::for_local_scan(adapter, &clean);
        let run = run_id(service.start_run(clean.context(), &request).expect("start"));
        let chunk = DiscoveryChunk {
            run_id: run,
            chunk_index: 0,
            claims: vec![static_claim(project_id, "orders", revision, recorded)],
        };
        service.submit_chunk(clean.context(), &chunk).expect("clean chunk");
        assert_eq!(row_count(&shared, "catalog_discovery_claims"), 1);
    }

    #[test]
    fn shared_sql_transactions_preserve_legacy_orders_and_replay_after_restart_and_supersession() {
        let (root, database) = private_database("restart");
        let shared = SqliteStore::open(&database, OpenOptions::default()).expect("open database");
        let scope = test_scope("spring-fixture");
        let selection = test_selection(scope.clone(), CatalogRunNamespace::RuntimeProducer);
        seed_authority(&shared, &selection);
        let identity = EndpointIdentity {
            project_id: selection.project_id(),
            application_component: "spring-fixture".to_owned(),
            transport: Transport::Http,
            binding_key: "default".to_owned(),
            method: HttpMethod::Post,
            route_template: "/orders".to_owned(),
        };
        let legacy_operation = OperationId::new();
        {
            let connection = shared.lock().expect("seed legacy operation");
            connection.execute(
                "INSERT INTO operations (operation_id, project_id, transport, method, route_template, application_component, binding_key, fingerprint_format_version, endpoint_fingerprint, created_at) VALUES (?1, ?2, 'http', 'POST', '/orders', 'spring-fixture', 'default', 1, ?3, '2026-10-04T00:00:00Z')",
                params![legacy_operation.as_uuid().as_bytes().to_vec(), selection.project_id().as_uuid().as_bytes().to_vec(), identity.fingerprint().expect("fingerprint").as_bytes().to_vec()],
            ).expect("seed finite legacy row");
        }

        let adapter = SqliteCatalogDiscoveryStore::new(shared.clone());
        let request = start_request(&scope, "stable-retry");
        let run = run_id(adapter.start_run_with_view(&selection, &request).expect("start"));
        let exact_retry =
            run_id(adapter.start_run_with_view(&selection, &request).expect("lost-grant retry"));
        assert_eq!(exact_retry, run);
        let mut latest = selection.clone();
        latest.owner_selection_id = *uuid::Uuid::now_v7().as_bytes();
        latest.owner_selection_epoch = 2;
        {
            let connection = shared.lock().expect("seed same-scope successor selection");
            connection.execute(
                "INSERT INTO catalog_owner_selections (owner_selection_id, project_id, selection_epoch, current_for_scope, verified_pack_digest, scope_digest, scope_json, revoked) VALUES (?1, ?2, 2, 0, ?3, ?4, ?5, 0)",
                params![latest.owner_selection_id.to_vec(), latest.project_id().as_uuid().as_bytes().to_vec(), latest.verified_pack_digest().as_bytes().to_vec(), latest.scope().digest().expect("scope digest").as_bytes().to_vec(), serde_json::to_string(latest.scope()).expect("scope JSON")],
            ).expect("insert successor selection");
        }
        assert!(adapter.start_run_with_view(&latest, &request).is_err());
        let preserved: (Vec<u8>, i64, String) = shared.lock().expect("check original run").query_row(
            "SELECT owner_selection_id, selection_epoch, status FROM catalog_discovery_runs WHERE run_id = ?1",
            [run.as_uuid().as_bytes().to_vec()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).expect("original run state");
        assert_eq!(preserved.0.as_slice(), selection.owner_selection_id().as_slice());
        assert_eq!(preserved.1, 1);
        assert_eq!(preserved.2, "open");
        {
            let connection = shared.lock().expect("tamper original run binding");
            connection.execute(
                "UPDATE catalog_discovery_runs SET owner_selection_id = ?2, selection_epoch = 2 WHERE run_id = ?1",
                params![run.as_uuid().as_bytes().to_vec(), latest.owner_selection_id.to_vec()],
            ).expect("change persisted owner binding");
        }
        assert!(adapter.start_run_with_view(&selection, &request).is_err());
        {
            let connection = shared.lock().expect("restore original run binding");
            connection.execute(
                "UPDATE catalog_discovery_runs SET owner_selection_id = ?2, selection_epoch = 1 WHERE run_id = ?1",
                params![run.as_uuid().as_bytes().to_vec(), selection.owner_selection_id().to_vec()],
            ).expect("restore original owner binding");
        }
        let mut local_selection = selection.clone();
        local_selection.namespace = CatalogRunNamespace::LocalStaticScanner;
        let local_run = run_id(
            adapter.start_run_with_view(&local_selection, &request).expect("separate namespace"),
        );
        assert_ne!(local_run, run);

        let claim = test_claim(selection.project_id(), "spring-fixture", "claim-1");
        let chunk = DiscoveryChunk { run_id: run, chunk_index: 0, claims: vec![claim] };
        adapter.submit_chunk_with_view(&selection, &chunk).expect("persist chunk");
        let finish = test_finish(run, &scope, std::slice::from_ref(&chunk));
        adapter.finish_run_with_view(&selection, &finish).expect("publish revision");
        let revision: CatalogRevisionId = {
            let connection = shared.lock().expect("read revision id");
            let bytes: Vec<u8> = connection
                .query_row(
                    "SELECT revision_id FROM catalog_discovery_runs WHERE run_id = ?1",
                    [run.as_uuid().as_bytes().to_vec()],
                    |row| row.get(0),
                )
                .expect("revision id");
            decode_id::<CatalogRevisionId>(&bytes).expect("revision UUID")
        };
        let summary = adapter
            .read_revision_summary(selection.project_id(), revision)
            .expect("persisted summary");
        assert_eq!(summary.completion, DiscoveryCompletion::Complete);
        {
            let connection = shared.lock().expect("supersede selection");
            connection.execute(
                "UPDATE catalog_owner_selections SET current_for_scope = 0 WHERE owner_selection_id = ?1",
                [selection.owner_selection_id().to_vec()],
            ).expect("supersede owner selection");
        }
        adapter
            .finish_run_with_view(&selection, &finish)
            .expect("exact terminal replay after supersession");

        {
            let connection = shared.lock().expect("activate successor selection");
            connection.execute(
                "UPDATE catalog_owner_selections SET current_for_scope = 1 WHERE owner_selection_id = ?1",
                [latest.owner_selection_id.to_vec()],
            ).expect("make successor selection current");
        }
        let superseded_run = run_id(
            adapter
                .start_run_with_view(&latest, &start_request(&scope, "superseded"))
                .expect("start successor run"),
        );
        let superseded_finish = test_finish(superseded_run, &scope, &[]);
        {
            let connection = shared.lock().expect("supersede successor");
            connection.execute(
                "UPDATE catalog_owner_selections SET current_for_scope = 0 WHERE owner_selection_id = ?1",
                [latest.owner_selection_id.to_vec()],
            ).expect("supersede successor selection");
        }
        adapter
            .finish_run_with_view(&latest, &superseded_finish)
            .expect("persist superseded terminal receipt");
        let superseded_status: String = shared
            .lock()
            .expect("inspect superseded")
            .query_row(
                "SELECT status FROM catalog_discovery_runs WHERE run_id = ?1",
                [superseded_run.as_uuid().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .expect("superseded run status");
        assert_eq!(superseded_status, "superseded");
        adapter
            .finish_run_with_view(&latest, &superseded_finish)
            .expect("replay superseded receipt");
        drop(adapter);
        drop(shared);

        let reopened =
            SqliteStore::open(&database, OpenOptions::default()).expect("reopen database");
        let replay = SqliteCatalogDiscoveryStore::new(reopened.clone());
        replay.finish_run_with_view(&selection, &finish).expect("terminal replay after restart");
        replay
            .finish_run_with_view(&latest, &superseded_finish)
            .expect("superseded replay after restart");
        let connection = reopened.lock().expect("inspect restarted history");
        let (legacy_count, legacy_id, catalog_id): (i64, Vec<u8>, Vec<u8>) = connection.query_row(
            "SELECT (SELECT COUNT(*) FROM operations WHERE project_id = ?1), (SELECT operation_id FROM operations WHERE project_id = ?1), (SELECT operation_id FROM catalog_operations WHERE project_id = ?1)",
            [selection.project_id().as_uuid().as_bytes().to_vec()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).expect("read legacy bridge");
        assert_eq!(legacy_count, 1);
        assert_eq!(legacy_id, legacy_operation.as_uuid().as_bytes());
        assert_eq!(catalog_id, legacy_id);
        drop(connection);
        drop(replay);
        drop(reopened);
        fs::remove_dir_all(root).expect("remove private fixture");
    }

    #[test]
    fn shared_sql_transactions_expire_refuse_revoked_corrupt_and_rollback_partial_chunk() {
        let shared = SqliteStore::open_in_memory(OpenOptions::default()).expect("store");
        let scope = test_scope("orders");
        let selection = test_selection(scope.clone(), CatalogRunNamespace::RuntimeProducer);
        seed_authority(&shared, &selection);
        let adapter = SqliteCatalogDiscoveryStore::new(shared.clone());
        adapter.set_test_now("2026-10-04T00:00:00Z");

        let expired_run = run_id(
            adapter
                .start_run_with_view(&selection, &start_request(&scope, "expired"))
                .expect("start expiring run"),
        );
        {
            let connection = shared.lock().expect("set expired deadline");
            connection.execute(
                "UPDATE catalog_discovery_run_deadlines SET started_at = '2000-01-01T00:00:00Z', expires_at = '2000-01-01T00:02:00Z' WHERE run_id = ?1",
                [expired_run.as_uuid().as_bytes().to_vec()],
            ).expect("set expired timestamp");
        }
        let expired_chunk = DiscoveryChunk {
            run_id: expired_run,
            chunk_index: 0,
            claims: vec![test_claim(selection.project_id(), "orders", "expired-claim")],
        };
        assert!(adapter.submit_chunk_with_view(&selection, &expired_chunk).is_err());
        let persisted_expiry: Option<String> = shared
            .lock()
            .expect("read expiry marker")
            .query_row(
                "SELECT expired_at FROM catalog_discovery_run_deadlines WHERE run_id = ?1",
                [expired_run.as_uuid().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .expect("expiry marker");
        assert!(persisted_expiry.is_some());
        adapter.set_test_now("1999-12-31T00:00:00Z");
        assert!(adapter.submit_chunk_with_view(&selection, &expired_chunk).is_err());

        adapter.set_test_now("2026-10-04T00:00:00Z");
        let rollback_run = run_id(
            adapter
                .start_run_with_view(&selection, &start_request(&scope, "rollback"))
                .expect("start rollback run"),
        );
        shared.lock().expect("install SQL failure trigger").execute_batch(
            "CREATE TRIGGER reject_test_claim BEFORE INSERT ON catalog_discovery_claims BEGIN SELECT RAISE(ABORT, 'injected rollback'); END;",
        ).expect("install trigger");
        let rollback_chunk = DiscoveryChunk {
            run_id: rollback_run,
            chunk_index: 0,
            claims: vec![test_claim(selection.project_id(), "orders", "rollback-claim")],
        };
        assert!(adapter.submit_chunk_with_view(&selection, &rollback_chunk).is_err());
        let rollback_state: (i64, i64, String) = shared.lock().expect("inspect rollback").query_row(
            "SELECT (SELECT COUNT(*) FROM catalog_discovery_chunks WHERE run_id = ?1), (SELECT COUNT(*) FROM catalog_discovery_claims WHERE run_id = ?1), status FROM catalog_discovery_runs WHERE run_id = ?1",
            [rollback_run.as_uuid().as_bytes().to_vec()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).expect("rollback state");
        assert_eq!((rollback_state.0, rollback_state.1, rollback_state.2.as_str()), (0, 0, "open"));

        let corrupt_run = run_id(
            adapter
                .start_run_with_view(&selection, &start_request(&scope, "corrupt"))
                .expect("start corrupt run"),
        );
        let corrupt_chunk = DiscoveryChunk {
            run_id: corrupt_run,
            chunk_index: 0,
            claims: vec![test_claim(selection.project_id(), "orders", "corrupt-claim")],
        };
        shared
            .lock()
            .expect("remove injected trigger")
            .execute_batch("DROP TRIGGER reject_test_claim")
            .expect("drop trigger");
        adapter.submit_chunk_with_view(&selection, &corrupt_chunk).expect("stage valid chunk");
        shared
            .lock()
            .expect("corrupt canonical row")
            .execute(
                "UPDATE catalog_discovery_claims SET canonical_json = '{broken' WHERE run_id = ?1",
                [corrupt_run.as_uuid().as_bytes().to_vec()],
            )
            .expect("inject canonical corruption");
        let corrupt_finish = test_finish(corrupt_run, &scope, std::slice::from_ref(&corrupt_chunk));
        assert!(adapter.finish_run_with_view(&selection, &corrupt_finish).is_err());

        let revoked_run = run_id(
            adapter
                .start_run_with_view(&selection, &start_request(&scope, "revoked"))
                .expect("start revoked run"),
        );
        shared
            .lock()
            .expect("revoke owner")
            .execute(
                "UPDATE catalog_owner_selections SET revoked = 1 WHERE owner_selection_id = ?1",
                [selection.owner_selection_id().to_vec()],
            )
            .expect("revoke persisted selection");
        assert!(
            adapter.start_run_with_view(&selection, &start_request(&scope, "revoked")).is_err()
        );
        assert!(
            adapter
                .finish_run_with_view(&selection, &test_finish(revoked_run, &scope, &[]))
                .is_err()
        );
        let revisions: i64 = shared
            .lock()
            .expect("count revisions")
            .query_row(
                "SELECT COUNT(*) FROM catalog_revisions WHERE project_id = ?1",
                [selection.project_id().as_uuid().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .expect("revision count");
        assert_eq!(revisions, 0);
    }

    #[test]
    fn catalog_first_orders_identity_is_shared_with_legacy_endpoint_table() {
        let store = SqliteStore::open_in_memory(OpenOptions::default()).expect("store");
        let project_id = ProjectId::new();
        {
            let connection = store.lock().expect("connection");
            connection
                .execute(
                    "INSERT INTO projects \
                     (project_id, canonical_repo_hash, display_name, created_at, last_opened_at, config_schema_version, effective_config_hash) \
                     VALUES (?1, ?2, 'test', '2026-10-04T00:00:00Z', '2026-10-04T00:00:00Z', 1, ?3)",
                    params![
                        project_id.as_uuid().as_bytes().to_vec(),
                        format!("b3:{}", "0".repeat(64)),
                        "0".repeat(64),
                    ],
                )
                .expect("project");
        }
        let mut connection = store.lock().expect("connection");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("transaction");
        let identity = EndpointIdentity {
            project_id,
            application_component: "spring-fixture".to_owned(),
            transport: Transport::Http,
            binding_key: "default".to_owned(),
            method: HttpMethod::Post,
            route_template: "/orders".to_owned(),
        };
        let fingerprint = identity.fingerprint().expect("fingerprint");
        let operation_id = find_or_create_operation(
            &transaction,
            &identity,
            fingerprint.as_bytes(),
            CorrelationId::new(),
        )
        .expect("catalog operation");
        let legacy_id: Vec<u8> = transaction
            .query_row(
                "SELECT operation_id FROM operations WHERE project_id = ?1",
                [project_id.as_uuid().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .expect("legacy operation");
        let catalog_id: Vec<u8> = transaction
            .query_row(
                "SELECT operation_id FROM catalog_operations WHERE project_id = ?1",
                [project_id.as_uuid().as_bytes().to_vec()],
                |row| row.get(0),
            )
            .expect("catalog operation");
        assert_eq!(legacy_id, operation_id.as_uuid().as_bytes());
        assert_eq!(catalog_id, legacy_id);
        transaction.commit().expect("commit");
    }
}
