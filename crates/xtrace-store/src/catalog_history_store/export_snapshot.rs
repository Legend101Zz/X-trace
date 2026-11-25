//! Bounded, consistent catalog reads for the viewer's preview and save operations.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use rusqlite::{Connection, ErrorCode, Row, TransactionBehavior, params, types::ValueRef};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use xtrace_application::catalog_discovery::history::{
    CatalogExportOperationIdentity, CatalogExportReadError as ReadError, CatalogExportRevision,
    CatalogExportScope, CatalogExportSnapshot, MAX_REVISION_OPERATIONS, RevisionEntry,
};
use xtrace_application::{CatalogChangeKind, CatalogSourceAvailability};
use xtrace_domain::catalog_discovery::{
    MAX_DISCOVERY_CLAIM_BYTES, MAX_DISCOVERY_RUN_CLAIM_BYTES, MAX_DISCOVERY_RUN_CLAIMS,
};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{
    CatalogRevisionId, ContentHash, EndpointIdentity, HttpMethod, OperationId, OperationVersionId,
    ProjectId, Transport,
};

use super::{
    OperationClaims, RevisionOperation, SqliteCatalogHistoryStore, hash, id, operation_view,
    project_claim, revision_entry, revision_from_row, revision_operation,
    revision_operation_from_row,
};
use crate::catalog_discovery_store::{CATALOG_CONTENT_DOMAIN, MAX_STORED_CLAIM_JSON_BYTES};
use crate::error::{StoreError, StoreErrorKind};

const MAX_EXPORT_INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_EXPORT_CLAIMS: usize = MAX_DISCOVERY_RUN_CLAIMS;
const MAX_EXPORT_CATALOG_SCOPES: usize = 4096;

impl SqliteCatalogHistoryStore {
    /// Reads one catalog revision and the selected evidence in one SQLite read transaction.
    ///
    /// The caller supplies its already admitted project ID. A single-operation export still
    /// needs the bounded revision-wide identity projection to preserve CLI export metadata.
    /// Only selected operations load claims and look up linked recordings.
    ///
    /// The callback can be invoked frequently, including inside SQLite. It should only inspect
    /// cancellation state or a deadline. Waiting for the shared connection lock or admitting its
    /// files cannot be interrupted here. Callers can use a separately opened read-only store.
    ///
    /// # Errors
    /// Returns a safe categorical outcome for missing, corrupt, oversized, cancelled or
    /// unavailable evidence. A failed read never returns a partial snapshot.
    pub fn read_export_snapshot(
        &self,
        project_id: ProjectId,
        revision: CatalogExportRevision,
        scope: CatalogExportScope,
        is_cancelled: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Result<CatalogExportSnapshot, ReadError> {
        check_cancelled(&is_cancelled)?;
        let mut connection = self.store.lock().map_err(store_error)?;
        check_cancelled(&is_cancelled)?;
        let is_cancelled = Arc::new(is_cancelled);
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sql_error)?;
        // The guarded read owns the connection exclusively. This module installs the only
        // progress handler on store connections and always clears it before releasing the lock.
        let progress = ProgressHandler(&transaction);
        let sql_cancelled = Arc::clone(&is_cancelled);
        transaction.progress_handler(1_024, Some(move || sql_cancelled()));
        let result =
            read_snapshot(&transaction, project_id, revision, scope, is_cancelled.as_ref());
        // Clear the hook even on errors, before ending the transaction or releasing the lock.
        drop(progress);
        let snapshot = result?;
        check_cancelled(is_cancelled.as_ref())?;
        transaction.commit().map_err(sql_error)?;
        Ok(snapshot)
    }
}

struct ProgressHandler<'a>(&'a Connection);

impl Drop for ProgressHandler<'_> {
    fn drop(&mut self) {
        self.0.progress_handler(0, None::<fn() -> bool>);
    }
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), ReadError> {
    if is_cancelled() { Err(ReadError::Cancelled) } else { Ok(()) }
}

fn store_error(error: StoreError) -> ReadError {
    match error.kind() {
        StoreErrorKind::Busy => ReadError::Busy,
        StoreErrorKind::Corruption => ReadError::Corrupt,
        _ => ReadError::Unavailable,
    }
}

fn sql_error(error: rusqlite::Error) -> ReadError {
    match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => ReadError::Busy,
        Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => ReadError::Corrupt,
        Some(ErrorCode::OperationInterrupted) => ReadError::Cancelled,
        Some(ErrorCode::TooBig) => ReadError::LimitExceeded,
        _ => ReadError::Unavailable,
    }
}

fn corrupt<T>(_: T) -> ReadError {
    ReadError::Corrupt
}

#[derive(Default)]
struct InputBudget {
    bytes: usize,
    claims: usize,
}

impl InputBudget {
    fn admit(&mut self, row: &Row<'_>, columns: usize) -> Result<(), ReadError> {
        // These are raw projected column bytes, including both claim encodings. The SQL
        // projections cap any single column before extraction, using octet_length for TEXT.
        // Check the aggregate on borrowed SQLite values before copying or decoding payloads.
        for index in 0..columns {
            self.bytes += match row.get_ref(index).map_err(corrupt)? {
                ValueRef::Text(value) | ValueRef::Blob(value) => value.len(),
                ValueRef::Integer(_) => size_of::<i64>(),
                ValueRef::Null => 0,
                ValueRef::Real(_) => return Err(ReadError::Corrupt),
            };
            if self.bytes > MAX_EXPORT_INPUT_BYTES {
                return Err(ReadError::LimitExceeded);
            }
        }
        Ok(())
    }
}

fn read_snapshot(
    connection: &Connection,
    project_id: ProjectId,
    revision: CatalogExportRevision,
    scope: CatalogExportScope,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CatalogExportSnapshot, ReadError> {
    let mut budget = InputBudget::default();
    let (revision, content_digest) = read_revision(connection, project_id, revision, &mut budget)?;
    let observed_identity = match scope {
        CatalogExportScope::ObservedOperation(id) => {
            check_cancelled(is_cancelled)?;
            Some(read_observed_identity(connection, project_id, id, &mut budget)?)
        }
        _ => None,
    };
    let selection = match scope {
        CatalogExportScope::All => OperationSelection::All,
        CatalogExportScope::Operation(id) => OperationSelection::Catalog(id),
        CatalogExportScope::ObservedOperation(_) => {
            OperationSelection::Observed(observed_identity.as_ref().ok_or(ReadError::Corrupt)?)
        }
    };
    let (catalog_identities, selected) = read_operation_index(
        connection,
        project_id,
        &revision,
        selection,
        content_digest,
        &mut budget,
        is_cancelled,
    )?;
    let catalog_scope = match scope {
        CatalogExportScope::ObservedOperation(_) => {
            CatalogExportScope::Operation(selected.first().ok_or(ReadError::OperationNotFound)?.id)
        }
        scope => scope,
    };
    let identities = selected.iter().map(|op| (op.id, &op.identity)).collect();
    let mut claims = read_claims(
        connection,
        project_id,
        revision.revision_id,
        catalog_scope,
        &identities,
        &mut budget,
        is_cancelled,
    )?;
    let mut linked_operation_ids = BTreeSet::new();
    let mut operations = Vec::with_capacity(selected.len());
    let mut observation = connection.prepare(OBSERVATION_SQL).map_err(sql_error)?;
    for op in selected {
        check_cancelled(is_cancelled)?;
        if has_linked_observation(&mut observation, &op.identity, None, &mut budget)? {
            linked_operation_ids.insert(op.id);
        }
        let claims = claims.remove(&op.id).unwrap_or_default().claims;
        operations.push(operation_view(op, claims).map_err(corrupt)?);
    }
    operations.sort_unstable_by(|a, b| {
        (&a.route_template, &a.method, &a.application_component, &a.binding_key, a.operation_id)
            .cmp(&(
                &b.route_template,
                &b.method,
                &b.application_component,
                &b.binding_key,
                b.operation_id,
            ))
    });
    Ok(CatalogExportSnapshot {
        observed_operation_id: match scope {
            CatalogExportScope::ObservedOperation(id) => Some(id),
            _ => None,
        },
        revision,
        catalog_identities,
        operations,
        linked_operation_ids,
    })
}

const REVISION_SQL: &str = "
    SELECT CASE WHEN length(r.revision_id) = 16 THEN r.revision_id END,
           r.ordinal,
           CASE WHEN length(r.parent_revision_id) = 16 THEN r.parent_revision_id END,
           CASE WHEN length(r.scope_digest) = 32 THEN r.scope_digest END,
           CASE WHEN length(r.source_revision_id) = 16 THEN r.source_revision_id END,
           r.operation_count,
           CASE WHEN length(r.run_id) = 16 THEN r.run_id END,
           CASE WHEN octet_length(r.created_at) BETWEEN 1 AND 64 THEN r.created_at END,
           CASE WHEN length(r.content_digest) = 32 THEN r.content_digest END,
           COALESCE(d.status = 'complete' AND d.revision_id = r.revision_id
             AND d.final_digest = r.final_digest AND length(r.final_digest) = 32
             AND d.scope_digest = r.scope_digest AND d.owner_selection_id = r.owner_selection_id
             AND d.source_revision_id IS r.source_revision_id
             AND (r.parent_revision_id IS NULL OR length(r.parent_revision_id) = 16)
             AND (r.source_revision_id IS NULL OR length(r.source_revision_id) = 16), 0)
    FROM catalog_revisions r
    LEFT JOIN catalog_discovery_runs d ON d.project_id = r.project_id AND d.run_id = r.run_id
    WHERE r.project_id = ?1";

const LATEST_PUBLICATION_SQL: &str = "
    WITH RECURSIVE scope_heads(publication_row, scope_digest) AS (
        SELECT publication_row, scope_digest FROM (
            SELECT rowid AS publication_row, scope_digest
            FROM catalog_revisions INDEXED BY catalog_revisions_scope_latest
            WHERE project_id = ?1
            ORDER BY scope_digest ASC, ordinal DESC
            LIMIT 1
        )
        UNION ALL
        SELECT head.rowid, head.scope_digest
        FROM scope_heads previous
        JOIN catalog_revisions head ON head.rowid = (
            SELECT rowid
            FROM catalog_revisions INDEXED BY catalog_revisions_scope_latest
            WHERE project_id = ?1 AND scope_digest > previous.scope_digest
            ORDER BY scope_digest ASC, ordinal DESC
            LIMIT 1
        )
        LIMIT ?2
    )
    SELECT MAX(publication_row), COUNT(*) FROM scope_heads";

fn latest_publication(connection: &Connection, project_id: ProjectId) -> Result<i64, ReadError> {
    // Each step seeks the newest ordinal in the next scope, independent of the size of
    // its revision history. Publication appends rows in serialized write transactions,
    // so a larger hidden rowid identifies the later committed scope head on this store.
    let (row, count): (Option<i64>, usize) = connection
        .query_row(
            LATEST_PUBLICATION_SQL,
            params![project_id.as_uuid().as_bytes(), MAX_EXPORT_CATALOG_SCOPES + 1],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sql_error)?;
    if count > MAX_EXPORT_CATALOG_SCOPES {
        return Err(ReadError::LimitExceeded);
    }
    row.ok_or(ReadError::NoCatalog)
}

fn read_revision(
    connection: &Connection,
    project_id: ProjectId,
    selection: CatalogExportRevision,
    budget: &mut InputBudget,
) -> Result<(RevisionEntry, ContentHash), ReadError> {
    let project = project_id.as_uuid();
    let (suffix, missing) = match selection {
        CatalogExportRevision::Latest => (" AND r.rowid = ?2", ReadError::Corrupt),
        CatalogExportRevision::Historical(_) => {
            (" AND r.revision_id = ?2", ReadError::RevisionNotFound)
        }
    };
    let mut query = connection.prepare(&format!("{REVISION_SQL}{suffix}")).map_err(sql_error)?;
    let mut rows = match selection {
        CatalogExportRevision::Latest => {
            let row = latest_publication(connection, project_id)?;
            query.query(params![project.as_bytes(), row])
        }
        CatalogExportRevision::Historical(revision) => {
            query.query(params![project.as_bytes(), revision.as_uuid().as_bytes()])
        }
    }
    .map_err(sql_error)?;
    let row = rows.next().map_err(sql_error)?.ok_or(missing)?;
    budget.admit(row, 10)?;
    if !row.get::<_, bool>(9).map_err(corrupt)? {
        return Err(ReadError::Corrupt);
    }
    let entry = revision_entry(revision_from_row(row).map_err(corrupt)?).map_err(corrupt)?;
    if entry.ordinal == 0 || OffsetDateTime::parse(&entry.created_at, &Rfc3339).is_err() {
        return Err(ReadError::Corrupt);
    }
    Ok((entry, hash(blob(row, 8)?).map_err(corrupt)?))
}

const OPERATIONS_SQL: &str = "
    SELECT CASE WHEN length(e.operation_id) = 16 THEN e.operation_id END,
           CASE WHEN length(e.operation_version_id) = 16 THEN e.operation_version_id END,
           CASE WHEN octet_length(e.change_kind) BETWEEN 1 AND 9 THEN e.change_kind END,
           CASE WHEN octet_length(e.source_availability) BETWEEN 1 AND 11 THEN e.source_availability END,
           CASE WHEN octet_length(o.application_component) BETWEEN 1 AND 128 THEN o.application_component END,
           CASE WHEN octet_length(o.binding_key) BETWEEN 1 AND 128 THEN o.binding_key END,
           CASE WHEN octet_length(o.method) BETWEEN 1 AND 16 THEN o.method END,
           CASE WHEN octet_length(o.route_template) BETWEEN 1 AND 1024 THEN o.route_template END,
           CASE WHEN octet_length(o.transport) = 4 THEN o.transport END,
           CASE WHEN length(v.version_digest) = 32 THEN v.version_digest END,
           CASE WHEN o.fingerprint_format = 1 AND length(o.endpoint_fingerprint) = 32
                THEN o.endpoint_fingerprint END
    FROM catalog_revision_entries e
    LEFT JOIN catalog_operations o ON o.project_id = e.project_id AND o.operation_id = e.operation_id
    LEFT JOIN catalog_operation_versions v ON v.project_id = e.project_id
         AND v.operation_id = e.operation_id AND v.operation_version_id = e.operation_version_id
    WHERE e.project_id = ?1 AND e.revision_id = ?2
    LIMIT ?3";

#[derive(Clone, Copy)]
enum OperationSelection<'a> {
    All,
    Catalog(OperationId),
    Observed(&'a EndpointIdentity),
}

fn read_operation_index(
    connection: &Connection,
    project_id: ProjectId,
    revision: &RevisionEntry,
    selection: OperationSelection<'_>,
    content_digest: ContentHash,
    budget: &mut InputBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(Vec<CatalogExportOperationIdentity>, Vec<RevisionOperation>), ReadError> {
    let count = usize::try_from(revision.operation_count).map_err(corrupt)?;
    if count > MAX_REVISION_OPERATIONS {
        return Err(ReadError::LimitExceeded);
    }
    let mut statement = connection.prepare(OPERATIONS_SQL).map_err(sql_error)?;
    let mut rows = statement
        .query(params![
            project_id.as_uuid().as_bytes(),
            revision.revision_id.as_uuid().as_bytes(),
            MAX_REVISION_OPERATIONS + 1
        ])
        .map_err(sql_error)?;
    let mut identities = Vec::with_capacity(count);
    let mut selected = Vec::new();
    let mut versions = BTreeMap::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        check_cancelled(is_cancelled)?;
        if identities.len() == MAX_REVISION_OPERATIONS {
            return Err(ReadError::LimitExceeded);
        }
        budget.admit(row, 11)?;
        let op = revision_operation(project_id, revision_operation_from_row(row).map_err(corrupt)?)
            .map_err(corrupt)?;
        id::<OperationVersionId>(op.version.as_bytes()).map_err(corrupt)?;
        let version_digest = op.version_digest.ok_or(ReadError::Corrupt)?;
        let fingerprint = *op.identity.fingerprint().map_err(corrupt)?.as_bytes();
        if fingerprint != blob(row, 10)? {
            return Err(ReadError::Corrupt);
        }
        match (op.change_kind, op.source_availability) {
            (CatalogChangeKind::Unknown, CatalogSourceAvailability::Unavailable) => {}
            (
                CatalogChangeKind::Added
                | CatalogChangeKind::Changed
                | CatalogChangeKind::Unchanged,
                CatalogSourceAvailability::Unverified,
            ) => {
                if versions.insert(fingerprint, version_digest).is_some() {
                    return Err(ReadError::Corrupt);
                }
            }
            _ => return Err(ReadError::Corrupt),
        }
        identities.push(CatalogExportOperationIdentity {
            application_component: op.identity.application_component.clone(),
            binding_key: op.identity.binding_key.clone(),
            method: op.identity.method.as_str().to_owned(),
            route_template: op.identity.route_template.clone(),
            operation_version_id: op.version.to_string(),
        });
        let include = match selection {
            OperationSelection::All => true,
            OperationSelection::Catalog(id) => id == op.id,
            OperationSelection::Observed(identity) => identity == &op.identity,
        };
        if include {
            selected.push(op);
        }
    }
    // The publisher hashes only operations this run reported, in fingerprint order.
    let mut digest = blake3::Hasher::new();
    digest.update(CATALOG_CONTENT_DOMAIN);
    for (fingerprint, version) in versions {
        digest.update(&fingerprint);
        digest.update(version.as_bytes());
    }
    if identities.len() != count || digest.finalize().as_bytes() != content_digest.as_bytes() {
        return Err(ReadError::Corrupt);
    }
    if !matches!(selection, OperationSelection::All) && selected.len() != 1 {
        return Err(ReadError::OperationNotFound);
    }
    Ok((identities, selected))
}

const CLAIMS_SQL: &str = "
    SELECT CASE WHEN length(rc.operation_id) = 16 THEN rc.operation_id END,
           CASE WHEN length(rc.claim_id) = 16 THEN rc.claim_id END,
           CASE WHEN length(c.claim_digest) = 32 THEN c.claim_digest END,
           CASE WHEN length(c.canonical_bytes) BETWEEN 1 AND ?3 THEN c.canonical_bytes END,
           CASE WHEN octet_length(c.canonical_json) BETWEEN 1 AND ?4 THEN c.canonical_json END
    FROM catalog_revision_claims rc
    LEFT JOIN catalog_claims c ON c.project_id = rc.project_id
        AND c.operation_id = rc.operation_id AND c.claim_id = rc.claim_id
    WHERE rc.project_id = ?1 AND rc.revision_id = ?2";

fn read_claims(
    connection: &Connection,
    project_id: ProjectId,
    revision_id: CatalogRevisionId,
    scope: CatalogExportScope,
    identities: &BTreeMap<OperationId, &EndpointIdentity>,
    budget: &mut InputBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<BTreeMap<OperationId, OperationClaims>, ReadError> {
    let suffix = match scope {
        CatalogExportScope::All => "",
        CatalogExportScope::Operation(_) => " AND rc.operation_id = ?5",
        CatalogExportScope::ObservedOperation(_) => return Err(ReadError::Corrupt),
    };
    let mut statement = connection.prepare(&format!("{CLAIMS_SQL}{suffix}")).map_err(sql_error)?;
    let project = project_id.as_uuid();
    let revision = revision_id.as_uuid();
    let mut rows = match scope {
        CatalogExportScope::All => statement.query(params![
            project.as_bytes(),
            revision.as_bytes(),
            MAX_DISCOVERY_CLAIM_BYTES,
            MAX_STORED_CLAIM_JSON_BYTES
        ]),
        CatalogExportScope::ObservedOperation(_) => return Err(ReadError::Corrupt),
        CatalogExportScope::Operation(op) => statement.query(params![
            project.as_bytes(),
            revision.as_bytes(),
            MAX_DISCOVERY_CLAIM_BYTES,
            MAX_STORED_CLAIM_JSON_BYTES,
            op.as_uuid().as_bytes()
        ]),
    }
    .map_err(sql_error)?;
    let mut by_operation = BTreeMap::<OperationId, OperationClaims>::new();
    while let Some(row) = rows.next().map_err(sql_error)? {
        check_cancelled(is_cancelled)?;
        budget.claims += 1;
        if budget.claims > MAX_EXPORT_CLAIMS {
            return Err(ReadError::LimitExceeded);
        }
        budget.admit(row, 5)?;
        let operation_id = id(blob(row, 0)?).map_err(corrupt)?;
        let identity = identities.get(&operation_id).ok_or(ReadError::Corrupt)?;
        let operation = by_operation.entry(operation_id).or_default();
        let canonical = blob(row, 3)?;
        operation.canonical_bytes += canonical.len();
        if operation.canonical_bytes > MAX_DISCOVERY_RUN_CLAIM_BYTES {
            return Err(ReadError::Corrupt);
        }
        operation.claims.push(
            project_claim(
                id(blob(row, 1)?).map_err(corrupt)?,
                blob(row, 2)?,
                canonical,
                text(row, 4)?,
                identity,
            )
            .map_err(corrupt)?,
        );
    }
    Ok(by_operation)
}

// A point lookup in the recording endpoint namespace. Declared routes are compared exactly,
// never reconstructed from a request URL or reconciled by route alone. Both this lookup and
// the backing observation/membership checks run in the caller's SQLite read transaction.
fn read_observed_identity(
    connection: &Connection,
    project_id: ProjectId,
    operation_id: OperationId,
    budget: &mut InputBudget,
) -> Result<EndpointIdentity, ReadError> {
    let mut statement = connection.prepare("SELECT
        CASE WHEN octet_length(application_component) BETWEEN 1 AND 128 THEN application_component END,
        CASE WHEN octet_length(binding_key) BETWEEN 1 AND 128 THEN binding_key END,
        CASE WHEN octet_length(method) BETWEEN 1 AND 16 THEN method END,
        CASE WHEN octet_length(route_template) BETWEEN 1 AND 1024 THEN route_template END,
        CASE WHEN transport = 'http' AND fingerprint_format_version = 1 AND length(endpoint_fingerprint) = 32 THEN endpoint_fingerprint END
        FROM operations WHERE project_id = ?1 AND operation_id = ?2").map_err(sql_error)?;
    let mut rows = statement
        .query(params![project_id.as_uuid().as_bytes(), operation_id.as_uuid().as_bytes()])
        .map_err(sql_error)?;
    let row = rows.next().map_err(sql_error)?.ok_or(ReadError::OperationNotFound)?;
    budget.admit(row, 5)?;
    let method_text = text(row, 2)?;
    let method = HttpMethod::parse(method_text)
        .filter(|method| method.as_str() == method_text)
        .ok_or(ReadError::Corrupt)?;
    let identity = EndpointIdentity {
        project_id,
        application_component: text(row, 0)?.to_owned(),
        binding_key: text(row, 1)?.to_owned(),
        transport: Transport::Http,
        method,
        route_template: text(row, 3)?.to_owned(),
    };
    if identity.fingerprint().map_err(corrupt)?.as_bytes() != blob(row, 4)? {
        return Err(ReadError::Corrupt);
    }
    let mut observation = connection.prepare(OBSERVATION_SQL).map_err(sql_error)?;
    if !has_linked_observation(&mut observation, &identity, Some(operation_id), budget)? {
        return Err(ReadError::OperationNotFound);
    }
    Ok(identity)
}

const OBSERVATION_SQL: &str = "
    SELECT CASE WHEN octet_length(e.disposition) = 6 THEN e.disposition END,
           CASE WHEN octet_length(e.application_component) BETWEEN 1 AND 128 THEN e.application_component END,
           CASE WHEN octet_length(e.binding_key) BETWEEN 1 AND 128 THEN e.binding_key END,
           CASE WHEN octet_length(e.method) BETWEEN 1 AND 16 THEN e.method END,
           CASE WHEN octet_length(e.route_template) BETWEEN 1 AND 1024 THEN e.route_template END,
           r.recording_id IS NOT NULL
    FROM operations o
    CROSS JOIN recording_endpoint_observations e INDEXED BY endpoint_observations_operation_recording
         ON e.project_id = o.project_id AND e.operation_id = o.operation_id
    LEFT JOIN recordings r ON r.project_id = e.project_id AND r.recording_id = e.recording_id
    WHERE o.project_id = ?1 AND o.application_component = ?2 AND o.binding_key = ?3
      AND o.transport = 'http' AND o.method = ?4 AND o.route_template = ?5
      AND (?6 IS NULL OR o.operation_id = ?6)
    LIMIT 1";

fn has_linked_observation(
    statement: &mut rusqlite::Statement<'_>,
    identity: &EndpointIdentity,
    observed_operation_id: Option<OperationId>,
    budget: &mut InputBudget,
) -> Result<bool, ReadError> {
    let observed_uuid = observed_operation_id.map(|id| id.as_uuid());
    let mut rows = statement
        .query(params![
            identity.project_id.as_uuid().as_bytes(),
            identity.application_component,
            identity.binding_key,
            identity.method.as_str(),
            identity.route_template,
            observed_uuid.as_ref().map(|id| id.as_bytes().as_slice())
        ])
        .map_err(sql_error)?;
    let Some(row) = rows.next().map_err(sql_error)? else {
        return Ok(false);
    };
    // The operation index identifies the endpoint and the observation index yields one
    // proof. The sidecar schema binds the tuple and forbids an operation ID on unmatched rows.
    budget.admit(row, 6)?;
    if text(row, 0)? != "linked"
        || text(row, 1)? != identity.application_component
        || text(row, 2)? != identity.binding_key
        || text(row, 3)? != identity.method.as_str()
        || text(row, 4)? != identity.route_template
        || !row.get::<_, bool>(5).map_err(corrupt)?
    {
        return Err(ReadError::Corrupt);
    }
    Ok(true)
}

fn blob<'a>(row: &'a Row<'_>, column: usize) -> Result<&'a [u8], ReadError> {
    row.get_ref(column).map_err(corrupt)?.as_blob().map_err(corrupt)
}

fn text<'a>(row: &'a Row<'_>, column: usize) -> Result<&'a str, ReadError> {
    row.get_ref(column).map_err(corrupt)?.as_str().map_err(corrupt)
}
