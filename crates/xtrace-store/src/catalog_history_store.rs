//! Read-only catalog history queries: revisions, runs, revision entries with their claims, and
//! the endpoints recordings were linked to.
//!
//! Claim JSON stays in the store. The application receives typed claim fields for export.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, OptionalExtension as _, params};
use xtrace_application::catalog_discovery::history::{
    CatalogHistoryPort, MAX_REVISION_OPERATIONS, ObservedOperation, OperationView, RevisionClaim,
    RevisionEntry, RunEntry,
};
use xtrace_application::{CatalogChangeKind, CatalogSourceAvailability, PortError, PortErrorKind};
use xtrace_domain::catalog_discovery::{
    ClaimSourceEvidence, MAX_DISCOVERY_CLAIM_BYTES, MAX_DISCOVERY_RUN_CLAIM_BYTES,
    MAX_DISCOVERY_RUN_CLAIMS,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    CatalogRevisionId, ContentHash, CorrelationId, EndpointIdentity, HttpMethod, OperationId,
    ProjectId, RunId, SourceRevisionId, Transport,
};

use crate::catalog_discovery_store::{MAX_STORED_CLAIM_JSON_BYTES, rebuild_revision_claim};
use crate::connection::SqliteStore;
use crate::error::StoreError;

/// Read view over the catalog tables.
#[derive(Clone, Debug)]
pub struct SqliteCatalogHistoryStore {
    store: SqliteStore,
}

impl SqliteCatalogHistoryStore {
    /// Creates the view.
    #[must_use]
    pub const fn new(store: SqliteStore) -> Self {
        Self { store }
    }
}

fn map_store(error: StoreError) -> PortError {
    PortError::new(PortErrorKind::Internal, error.message().to_owned(), error.correlation_id())
}

fn map_sql(error: rusqlite::Error) -> PortError {
    map_store(StoreError::from_rusqlite(error, CorrelationId::new()))
}

fn corrupt() -> PortError {
    PortError::new(
        PortErrorKind::Corruption,
        "catalog history evidence is inconsistent",
        CorrelationId::new(),
    )
}

fn id<T: From<uuid::Uuid>>(bytes: &[u8]) -> Result<T, PortError> {
    let uuid = uuid::Uuid::from_slice(bytes).map_err(|_| corrupt())?;
    if uuid.get_version_num() != 7 {
        return Err(corrupt());
    }
    Ok(T::from(uuid))
}

fn hash(bytes: &[u8]) -> Result<ContentHash, PortError> {
    ContentHash::from_digest_bytes(bytes).ok_or_else(corrupt)
}

fn bytes(value: &impl AsRefUuid) -> Vec<u8> {
    value.uuid_bytes()
}

/// Local shim so one helper serves every id newtype.
trait AsRefUuid {
    fn uuid_bytes(&self) -> Vec<u8>;
}
macro_rules! uuid_bytes_impl {
    ($($t:ty),*) => {$(impl AsRefUuid for $t { fn uuid_bytes(&self) -> Vec<u8> { self.as_uuid().as_bytes().to_vec() } })*};
}
uuid_bytes_impl!(ProjectId, CatalogRevisionId, RunId);

type RevisionRow = (Vec<u8>, i64, Option<Vec<u8>>, Vec<u8>, Option<Vec<u8>>, i64, Vec<u8>, String);

fn revision_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RevisionRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

const REVISION_COLUMNS: &str = "revision_id, ordinal, parent_revision_id, scope_digest, source_revision_id, operation_count, run_id, created_at";

fn revision_entry(row: RevisionRow) -> Result<RevisionEntry, PortError> {
    Ok(RevisionEntry {
        revision_id: id(&row.0)?,
        ordinal: u32::try_from(row.1).map_err(|_| corrupt())?,
        parent_revision_id: row.2.as_deref().map(id::<CatalogRevisionId>).transpose()?,
        scope_digest: hash(&row.3)?,
        source_revision_id: row.4.as_deref().map(id::<SourceRevisionId>).transpose()?,
        operation_count: u32::try_from(row.5).map_err(|_| corrupt())?,
        run_id: id(&row.6)?,
        created_at: row.7,
        completion: "complete",
        pack_status: "dev_unsigned",
    })
}

struct RevisionOperation {
    id: OperationId,
    version: uuid::Uuid,
    change_kind: CatalogChangeKind,
    source_availability: CatalogSourceAvailability,
    identity: EndpointIdentity,
}

impl CatalogHistoryPort for SqliteCatalogHistoryStore {
    fn list_revisions(
        &self,
        project_id: ProjectId,
        limit: u32,
    ) -> Result<Vec<RevisionEntry>, PortError> {
        let connection = self.store.lock().map_err(map_store)?;
        let mut statement = connection
            .prepare(&format!(
                "SELECT {REVISION_COLUMNS} FROM catalog_revisions WHERE project_id = ?1 \
                 ORDER BY revision_id DESC LIMIT ?2"
            ))
            .map_err(map_sql)?;
        let rows = statement
            .query_map(params![bytes(&project_id), i64::from(limit)], revision_from_row)
            .map_err(map_sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sql)?;
        rows.into_iter().map(revision_entry).collect()
    }

    fn list_runs(&self, project_id: ProjectId, limit: u32) -> Result<Vec<RunEntry>, PortError> {
        let connection = self.store.lock().map_err(map_store)?;
        let mut statement = connection
            .prepare(
                "SELECT run_id, status, scope_digest, accepted_claim_count, rejected_claim_count, limitation_codes_json, revision_id \
                 FROM catalog_discovery_runs WHERE project_id = ?1 ORDER BY run_id DESC LIMIT ?2",
            )
            .map_err(map_sql)?;
        let rows = statement
            .query_map(params![bytes(&project_id), i64::from(limit)], run_from_row)
            .map_err(map_sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sql)?;
        rows.into_iter().map(run_entry).collect()
    }

    fn revision(
        &self,
        project_id: ProjectId,
        revision_id: CatalogRevisionId,
    ) -> Result<Option<RevisionEntry>, PortError> {
        let connection = self.store.lock().map_err(map_store)?;
        let row = connection
            .query_row(
                &format!(
                    "SELECT {REVISION_COLUMNS} FROM catalog_revisions WHERE project_id = ?1 AND revision_id = ?2"
                ),
                params![bytes(&project_id), bytes(&revision_id)],
                revision_from_row,
            )
            .optional()
            .map_err(map_sql)?;
        row.map(revision_entry).transpose()
    }

    fn run(&self, project_id: ProjectId, run_id: RunId) -> Result<Option<RunEntry>, PortError> {
        let connection = self.store.lock().map_err(map_store)?;
        let row = connection
            .query_row(
                "SELECT run_id, status, scope_digest, accepted_claim_count, rejected_claim_count, limitation_codes_json, revision_id \
                 FROM catalog_discovery_runs WHERE project_id = ?1 AND run_id = ?2",
                params![bytes(&project_id), bytes(&run_id)],
                run_from_row,
            )
            .optional()
            .map_err(map_sql)?;
        row.map(run_entry).transpose()
    }

    fn revision_operations(
        &self,
        project_id: ProjectId,
        revision_id: CatalogRevisionId,
    ) -> Result<Vec<OperationView>, PortError> {
        let connection = self.store.lock().map_err(map_store)?;
        let mut statement = connection
            .prepare(
                "SELECT e.operation_id, e.operation_version_id, e.change_kind, e.source_availability, \
                        o.application_component, o.binding_key, o.method, o.route_template, o.transport \
                 FROM catalog_revision_entries e \
                 JOIN catalog_operations o ON o.project_id = e.project_id AND o.operation_id = e.operation_id \
                 WHERE e.project_id = ?1 AND e.revision_id = ?2 \
                 ORDER BY o.route_template, o.method, o.application_component, o.binding_key, e.operation_id \
                 LIMIT ?3",
            )
            .map_err(map_sql)?;
        let rows = statement
            .query_map(
                params![
                    bytes(&project_id),
                    bytes(&revision_id),
                    i64::try_from(MAX_REVISION_OPERATIONS + 1).map_err(|_| corrupt())?
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                    ))
                },
            )
            .map_err(map_sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sql)?;
        if rows.len() > MAX_REVISION_OPERATIONS {
            return Err(corrupt());
        }
        let mut operations = Vec::with_capacity(rows.len());
        for row in rows {
            let change_kind = match row.2.as_str() {
                "added" => CatalogChangeKind::Added,
                "unchanged" => CatalogChangeKind::Unchanged,
                "changed" => CatalogChangeKind::Changed,
                "removed" => CatalogChangeKind::Removed,
                "unknown" => CatalogChangeKind::Unknown,
                _ => return Err(corrupt()),
            };
            let source_availability = match row.3.as_str() {
                "unverified" => CatalogSourceAvailability::Unverified,
                "unavailable" => CatalogSourceAvailability::Unavailable,
                _ => return Err(corrupt()),
            };
            let method = HttpMethod::parse(&row.6)
                .filter(|method| method.as_str() == row.6)
                .ok_or_else(corrupt)?;
            if row.8 != Transport::Http.as_str() {
                return Err(corrupt());
            }
            operations.push(RevisionOperation {
                id: id(&row.0)?,
                version: uuid::Uuid::from_slice(&row.1).map_err(|_| corrupt())?,
                change_kind,
                source_availability,
                identity: EndpointIdentity {
                    project_id,
                    application_component: row.4,
                    binding_key: row.5,
                    method,
                    route_template: row.7,
                    transport: Transport::Http,
                },
            });
        }
        let identities = operations.iter().map(|op| (op.id, &op.identity)).collect();
        let mut claims = load_claims(&connection, project_id, revision_id, &identities)?;
        let mut views = Vec::with_capacity(operations.len());
        for op in operations {
            let claims = claims.remove(&op.id).unwrap_or_default();
            // The publisher retains omitted parent entries as unknown and unavailable,
            // without linking the parent's claims into the new revision.
            let claims_available = !(claims.is_empty()
                && op.change_kind == CatalogChangeKind::Unknown
                && op.source_availability == CatalogSourceAvailability::Unavailable);
            let summary = ClaimSummary::from_claims(&claims);
            views.push(OperationView {
                operation_id: op.id,
                operation_version_id: op.version.to_string(),
                application_component: op.identity.application_component,
                binding_key: op.identity.binding_key,
                method: op.identity.method.as_str().to_owned(),
                route_template: op.identity.route_template,
                change_kind: op.change_kind,
                source_availability: op.source_availability,
                provenance: summary.provenance.into_iter().collect(),
                confidence_basis_points: summary.confidence,
                limitation_codes: summary.limitations.into_iter().collect(),
                handler_conflict: summary.handlers.len() > 1,
                handlers: summary.handlers.into_iter().collect(),
                claim_count: claims.len(),
                source_path: summary.source.as_ref().map(|(path, _)| path.clone()),
                source_line: summary.source.map(|(_, line)| line),
                claims_available,
                claims,
            });
        }
        Ok(views)
    }

    fn observed_operations(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<ObservedOperation>, PortError> {
        let connection = self.store.lock().map_err(map_store)?;
        let mut statement = connection
            .prepare(
                "SELECT o.application_component, o.binding_key, o.method, o.route_template, COUNT(e.recording_id) \
                 FROM operations o \
                 JOIN recording_endpoint_observations e ON e.project_id = o.project_id AND e.operation_id = o.operation_id AND e.disposition = 'linked' \
                 WHERE o.project_id = ?1 \
                 GROUP BY o.operation_id \
                 ORDER BY o.route_template, o.method, o.application_component, o.binding_key LIMIT 4097",
            )
            .map_err(map_sql)?;
        let rows = statement
            .query_map(params![bytes(&project_id)], |row| {
                Ok(ObservedOperation {
                    application_component: row.get(0)?,
                    binding_key: row.get(1)?,
                    method: row.get(2)?,
                    route_template: row.get(3)?,
                    recording_count: usize::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
                })
            })
            .map_err(map_sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sql)?;
        if rows.len() > MAX_REVISION_OPERATIONS {
            return Err(corrupt());
        }
        Ok(rows)
    }
}

type RunRow = (Vec<u8>, String, Vec<u8>, i64, i64, Option<String>, Option<Vec<u8>>);

fn run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RunRow> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?))
}

fn run_entry(row: RunRow) -> Result<RunEntry, PortError> {
    let limitation_codes: Vec<String> = match row.5.as_deref() {
        Some(json) => serde_json::from_str(json).map_err(|_| corrupt())?,
        None => Vec::new(),
    };
    Ok(RunEntry {
        run_id: id(&row.0)?,
        status: row.1,
        scope_digest: hash(&row.2)?,
        accepted_claims: u32::try_from(row.3).map_err(|_| corrupt())?,
        rejected_claims: u32::try_from(row.4).map_err(|_| corrupt())?,
        limitation_codes,
        revision_id: row.6.as_deref().map(id::<CatalogRevisionId>).transpose()?,
    })
}

#[derive(Default)]
struct ClaimSummary {
    provenance: BTreeSet<String>,
    limitations: BTreeSet<String>,
    handlers: BTreeSet<String>,
    confidence: u16,
    source: Option<(String, u32)>,
}

impl ClaimSummary {
    fn from_claims(claims: &[RevisionClaim]) -> Self {
        let mut summary = Self::default();
        for claim in claims {
            summary.provenance.insert(claim.provenance.clone());
            summary.limitations.extend(claim.limitation_codes.iter().cloned());
            summary.handlers.extend(claim.handler_symbol.iter().cloned());
            summary.confidence = summary.confidence.max(claim.confidence_basis_points.unwrap_or(0));
            if summary.source.is_none() {
                summary.source = match claim.source_evidence.first() {
                    Some(
                        ClaimSourceEvidence::StaticSnapshot { relative_path, start_line, .. }
                        | ClaimSourceEvidence::LoadedClassBound { relative_path, start_line, .. }
                        | ClaimSourceEvidence::RuntimeHint {
                            relative_path: Some(relative_path),
                            start_line: Some(start_line),
                            ..
                        },
                    ) => Some((relative_path.clone(), *start_line)),
                    _ => None,
                };
            }
        }
        summary
    }
}

#[derive(Default)]
struct OperationClaims {
    canonical_bytes: usize,
    claims: Vec<([u8; 32], RevisionClaim)>,
}

fn load_claims(
    connection: &Connection,
    project_id: ProjectId,
    revision_id: CatalogRevisionId,
    identities: &BTreeMap<OperationId, &EndpointIdentity>,
) -> Result<BTreeMap<OperationId, Vec<RevisionClaim>>, PortError> {
    // A revision can combine scopes, so apply the writer's limits per operation.
    // The claim count and catalog_claims JSON row cap also bound JSON to 64 MiB per operation.
    // Stream the revision index without a SQL sort. Admit lengths before fetching each payload.
    let mut statement = connection
        .prepare(
            "SELECT rc.operation_id, rc.claim_id, \
                    CASE WHEN length(c.claim_digest) = 32 THEN c.claim_digest END, \
                    CASE WHEN length(c.canonical_bytes) BETWEEN 1 AND ?3 THEN c.canonical_bytes END, \
                    CASE WHEN length(CAST(c.canonical_json AS BLOB)) BETWEEN 1 AND ?4 THEN c.canonical_json END \
             FROM catalog_revision_claims rc \
             LEFT JOIN catalog_claims c ON c.project_id = rc.project_id \
                 AND c.operation_id = rc.operation_id AND c.claim_id = rc.claim_id \
             WHERE rc.project_id = ?1 AND rc.revision_id = ?2",
        )
        .map_err(map_sql)?;
    let mut rows = statement
        .query(params![
            bytes(&project_id),
            bytes(&revision_id),
            MAX_DISCOVERY_CLAIM_BYTES,
            MAX_STORED_CLAIM_JSON_BYTES
        ])
        .map_err(map_sql)?;
    let mut by_operation = BTreeMap::<OperationId, OperationClaims>::new();
    while let Some(row) = rows.next().map_err(map_sql)? {
        let operation_id = id(&row.get::<_, Vec<u8>>(0).map_err(map_sql)?)?;
        let identity = identities.get(&operation_id).ok_or_else(corrupt)?;
        let operation = by_operation.entry(operation_id).or_default();
        if operation.claims.len() >= MAX_DISCOVERY_RUN_CLAIMS {
            return Err(corrupt());
        }
        let canonical = row.get_ref(3).map_err(map_sql)?.as_blob().map_err(|_| corrupt())?;
        operation.canonical_bytes += canonical.len();
        if operation.canonical_bytes > MAX_DISCOVERY_RUN_CLAIM_BYTES {
            return Err(corrupt());
        }
        let json = row.get_ref(4).map_err(map_sql)?.as_str().map_err(|_| corrupt())?;
        let digest = row.get_ref(2).map_err(map_sql)?.as_blob().map_err(|_| corrupt())?;
        let claim =
            rebuild_revision_claim(digest, canonical, json, identity).map_err(|_| corrupt())?;
        let serde_json::Value::String(provenance) =
            serde_json::to_value(claim.provenance()).map_err(|_| corrupt())?
        else {
            return Err(corrupt());
        };
        operation.claims.push((
            digest.try_into().map_err(|_| corrupt())?,
            RevisionClaim {
                claim_id: id(&row.get::<_, Vec<u8>>(1).map_err(map_sql)?)?,
                provenance,
                handler_symbol: claim.handler_symbol().map(str::to_owned),
                confidence_basis_points: claim.confidence_basis_points(),
                limitation_codes: claim.limitation_codes().to_vec(),
                source_evidence: claim.source_evidence().to_vec(),
            },
        ));
    }
    Ok(by_operation
        .into_iter()
        .map(|(id, mut operation)| {
            // The history summary uses the first available location in claim digest order.
            operation.claims.sort_unstable_by_key(|(digest, claim)| (*digest, claim.claim_id));
            (id, operation.claims.into_iter().map(|(_, claim)| claim).collect())
        })
        .collect())
}
