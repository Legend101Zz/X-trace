//! Read-only catalog history queries: revisions, runs, revision entries with their claims, and
//! the endpoints recordings were linked to.
//!
//! Claim JSON is parsed here (and only here and in the discovery store) because the application
//! projection deliberately omits it; nothing in this file writes.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, OptionalExtension as _, params};
use xtrace_application::catalog_discovery::history::{
    CatalogHistoryPort, MAX_REVISION_OPERATIONS, ObservedOperation, OperationView, RevisionEntry,
    RunEntry,
};
use xtrace_application::{CatalogChangeKind, CatalogSourceAvailability, PortError, PortErrorKind};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    CatalogRevisionId, ContentHash, CorrelationId, OperationId, ProjectId, RunId, SourceRevisionId,
};

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
        let claims = load_claims(&connection, project_id, revision_id)?;
        let mut statement = connection
            .prepare(
                "SELECT e.operation_id, e.operation_version_id, e.change_kind, e.source_availability, \
                        o.application_component, o.binding_key, o.method, o.route_template \
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
                    ))
                },
            )
            .map_err(map_sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sql)?;
        if rows.len() > MAX_REVISION_OPERATIONS {
            return Err(corrupt());
        }
        let mut views = Vec::with_capacity(rows.len());
        for row in rows {
            let operation_id: OperationId = id(&row.0)?;
            let version: uuid::Uuid = uuid::Uuid::from_slice(&row.1).map_err(|_| corrupt())?;
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
            let summary = claims.get(&operation_id).cloned().unwrap_or_default();
            views.push(OperationView {
                operation_id,
                operation_version_id: version.to_string(),
                application_component: row.4,
                binding_key: row.5,
                method: row.6,
                route_template: row.7,
                change_kind,
                source_availability,
                provenance: summary.provenance.into_iter().collect(),
                confidence_basis_points: summary.confidence,
                limitation_codes: summary.limitations.into_iter().collect(),
                handler_conflict: summary.handlers.len() > 1,
                handlers: summary.handlers.into_iter().collect(),
                claim_count: summary.claims,
                source_path: summary.source.as_ref().map(|(path, _)| path.clone()),
                source_line: summary.source.map(|(_, line)| line),
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

#[derive(Clone, Debug, Default)]
struct ClaimSummary {
    provenance: BTreeSet<String>,
    limitations: BTreeSet<String>,
    handlers: BTreeSet<String>,
    confidence: u16,
    claims: usize,
    source: Option<(String, u32)>,
}

fn load_claims(
    connection: &Connection,
    project_id: ProjectId,
    revision_id: CatalogRevisionId,
) -> Result<BTreeMap<OperationId, ClaimSummary>, PortError> {
    let mut statement = connection
        .prepare(
            "SELECT rc.operation_id, c.canonical_json FROM catalog_revision_claims rc \
             JOIN catalog_claims c ON c.project_id = rc.project_id AND c.claim_id = rc.claim_id \
             WHERE rc.project_id = ?1 AND rc.revision_id = ?2 ORDER BY rc.operation_id, c.claim_digest",
        )
        .map_err(map_sql)?;
    let rows = statement
        .query_map(params![bytes(&project_id), bytes(&revision_id)], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(map_sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_sql)?;
    let mut by_operation: BTreeMap<OperationId, ClaimSummary> = BTreeMap::new();
    for (operation, json) in rows {
        let value: serde_json::Value = serde_json::from_str(&json).map_err(|_| corrupt())?;
        let summary = by_operation.entry(id(&operation)?).or_default();
        summary.claims += 1;
        if let Some(provenance) = value.get("provenance").and_then(serde_json::Value::as_str) {
            summary.provenance.insert(provenance.to_owned());
        }
        if let Some(handler) = value.get("handler_symbol").and_then(serde_json::Value::as_str) {
            summary.handlers.insert(handler.to_owned());
        }
        if let Some(codes) = value.get("limitation_codes").and_then(serde_json::Value::as_array) {
            summary
                .limitations
                .extend(codes.iter().filter_map(serde_json::Value::as_str).map(str::to_owned));
        }
        if let Some(confidence) =
            value.get("confidence_basis_points").and_then(serde_json::Value::as_u64)
        {
            summary.confidence = summary.confidence.max(u16::try_from(confidence).unwrap_or(0));
        }
        if summary.source.is_none()
            && let Some(first) = value
                .get("source_evidence")
                .and_then(serde_json::Value::as_array)
                .and_then(|items| items.first())
            && let (Some(path), Some(line)) = (
                first.get("relative_path").and_then(serde_json::Value::as_str),
                first.get("start_line").and_then(serde_json::Value::as_u64),
            )
        {
            summary.source = Some((path.to_owned(), u32::try_from(line).unwrap_or(0)));
        }
    }
    Ok(by_operation)
}
