//! Transactional storage for the bounded catalog-discovery transcript.
//!
//! This adapter accepts only the opaque application admission token. The
//! shipped application refuses admission, so no producer claim can create
//! catalog state until owner selection, verified-pack, and source authorities
//! are wired into that boundary.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{OptionalExtension as _, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use xtrace_application::{
    AdmittedCatalogSelection, CatalogChangeKind, CatalogDiscoveryWritePort, CatalogOperationFilter,
    CatalogOperationRecord, CatalogReadPort, CatalogRevisionSummary, CatalogSourceAvailability,
    PortError, PortErrorKind,
};
use xtrace_domain::catalog_discovery::{
    ClaimProvenance, ClaimSourceEvidence, DiscoveryChunk, DiscoveryCompletion, DiscoveryProofError,
    DiscoveryRunFinish, DiscoveryRunGrant, DiscoveryRunStartRequest, DiscoveryScope,
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
}

impl SqliteCatalogDiscoveryStore {
    /// Creates a catalog view over the shared SQLite handle.
    #[must_use]
    pub const fn new(store: SqliteStore) -> Self {
        Self { store }
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
        // Exact retries are checked against their original immutable
        // selection even if a newer selection now covers the same scope.
        verify_selection(&transaction, selection, false)?;
        let request_bytes = request.canonical_bytes().map_err(|_| validation_error())?;
        let request_digest = ContentHash::of_bytes(&request_bytes);
        if let Some(existing) = transaction
            .query_row(
                "SELECT run_id, request_bytes, request_digest, scope_digest, source_revision_id, protocol_minor, pinned_source_digest FROM catalog_discovery_runs \
                 WHERE project_id = ?1 AND runtime_session_id = ?2 AND verified_pack_digest = ?3 \
                   AND owner_selection_id = ?4 AND run_hint = ?5",
                params![
                    selection.project_id().as_uuid().as_bytes().to_vec(),
                    selection.runtime_session_id().as_uuid().as_bytes().to_vec(),
                    selection.verified_pack_digest().as_bytes().to_vec(),
                    selection.owner_selection_id().to_vec(),
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
                    ))
                },
            )
            .optional()
            .map_err(|error| map_rusqlite(error, correlation_id))?
        {
            if existing.1 != request_bytes {
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
            let run_id = decode_id::<RunId>(&existing.0).ok_or_else(corruption_error)?;
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

        verify_selection(&transaction, selection, true)?;
        let run_id = RunId::new();
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
                    request.run_hint,
                    request_bytes,
                    request_digest.as_bytes().to_vec(),
                    scope_digest.as_bytes().to_vec(),
                    scope_json,
                    source_revision_id.map(|id| id.as_uuid().as_bytes().to_vec()),
                    pinned_source_digest.map(|hash| hash.as_bytes().to_vec()),
                ],
            )
            .map_err(|error| map_rusqlite(error, correlation_id))?;
        transaction.commit().map_err(|error| map_rusqlite(error, correlation_id))?;
        Ok(DiscoveryRunGrant::Admitted { run_id, scope_digest, source_revision_id })
    }

    fn submit_chunk(
        &self,
        selection: &AdmittedCatalogSelection,
        chunk: &DiscoveryChunk,
    ) -> Result<(), PortError> {
        let canonical_chunk = chunk.canonical_bytes().map_err(|_| validation_error())?;
        let digest = ContentHash::of_bytes(&canonical_chunk);
        if chunk.claims.iter().any(|claim| {
            claim.source_evidence().iter().any(|evidence| {
                matches!(
                    evidence,
                    ClaimSourceEvidence::StaticSnapshot { .. }
                        | ClaimSourceEvidence::LoadedClassBound { .. }
                )
            })
        }) {
            return Err(PortError::new(
                PortErrorKind::Validation,
                "catalog source proof is unavailable",
                CorrelationId::new(),
            ));
        }
        if chunk.claims.iter().any(|claim| claim.operation().project_id != selection.project_id()) {
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

    fn finish_run(
        &self,
        selection: &AdmittedCatalogSelection,
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
        let chunks = load_and_verify_chunks(&transaction, finish.run_id, selection.project_id())?;
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
            if run.status == status
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
            return Err(conflict_error());
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
            completion: DiscoveryCompletion::Complete,
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
            if identity.fingerprint().map(|hash| hash.as_bytes().to_vec())
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
    selection: &AdmittedCatalogSelection,
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
    selection: &AdmittedCatalogSelection,
    run: &RunRow,
    require_current: bool,
) -> Result<(), PortError> {
    if run.project_id != selection.project_id()
        || run.session_id != selection.runtime_session_id()
        || run.pack_digest != selection.verified_pack_digest()
        || run.protocol_minor != selection.protocol_minor()
        || run.owner_selection_id != *selection.owner_selection_id()
        || run.selection_epoch != selection.owner_selection_epoch()
        || run.source_revision_id != selection.source_revision_id()
        || run.pinned_source_digest != selection.pinned_source_digest()
        || run.scope.canonical_bytes().ok() != selection.scope().canonical_bytes().ok()
    {
        return Err(conflict_error());
    }
    verify_selection(transaction, selection, require_current)
}

fn load_run(transaction: &Transaction<'_>, run_id: RunId) -> Result<RunRow, PortError> {
    let row = transaction
        .query_row(
            "SELECT project_id, runtime_session_id, verified_pack_digest, protocol_minor, owner_selection_id, selection_epoch, scope_digest, scope_json, source_revision_id, pinned_source_digest, accepted_claim_count, accepted_claim_bytes, status \
             FROM catalog_discovery_runs WHERE run_id = ?1",
            params![run_id.as_uuid().as_bytes().to_vec()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, i64>(3)?, row.get::<_, Vec<u8>>(4)?, row.get::<_, i64>(5)?, row.get::<_, Vec<u8>>(6)?, row.get::<_, String>(7)?, row.get::<_, Option<Vec<u8>>>(8)?, row.get::<_, Option<Vec<u8>>>(9)?, row.get::<_, i64>(10)?, row.get::<_, i64>(11)?, row.get::<_, String>(12)?)),
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
        if chunk.digest().map(|hash| hash.as_bytes().to_vec()) != Some(stored_digest) {
            return Err(corruption_error());
        }
        chunks.push(chunk);
    }
    Ok(chunks)
}

fn publish_revision(
    transaction: &Transaction<'_>,
    selection: &AdmittedCatalogSelection,
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
    if tuple == ("spring-fixture", "default", "http", "POST", "/orders") {
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
        StoreErrorKind::Busy | StoreErrorKind::Resource => PortErrorKind::Resource,
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
