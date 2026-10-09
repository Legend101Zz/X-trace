//! Durable owner selections for user-invoked local static scans (AD-1).
//!
//! One transaction retires the previous current selection of the same project and scope and
//! inserts the new one with the next revocation epoch, so the single-current-selection unique
//! index and the write port's epoch check always see a consistent pair.

use rusqlite::{OptionalExtension as _, TransactionBehavior, params};
use xtrace_application::catalog_discovery::admission::{
    LocalScanSelection, OwnerSelectionPort, RecordedOwnerSelection,
};
use xtrace_application::{PortError, PortErrorKind};
use xtrace_domain::ids::Id as _;
use xtrace_domain::CorrelationId;

use crate::connection::SqliteStore;
use crate::error::StoreError;

/// Owner-selection persistence over the shared SQLite handle.
#[derive(Clone, Debug)]
pub struct SqliteCatalogAdmissionStore {
    store: SqliteStore,
}

impl SqliteCatalogAdmissionStore {
    /// Creates the view.
    #[must_use]
    pub const fn new(store: SqliteStore) -> Self {
        Self { store }
    }
}

fn map_store(error: StoreError) -> PortError {
    PortError::new(PortErrorKind::Internal, error.message().to_owned(), error.correlation_id())
}

fn map_sql(error: rusqlite::Error, correlation_id: CorrelationId) -> PortError {
    map_store(StoreError::from_rusqlite(error, correlation_id))
}

fn invalid(message: &'static str) -> PortError {
    PortError::new(PortErrorKind::Validation, message, CorrelationId::new())
}

impl OwnerSelectionPort for SqliteCatalogAdmissionStore {
    fn record_local_scan_selection(
        &self,
        selection: &LocalScanSelection,
    ) -> Result<RecordedOwnerSelection, PortError> {
        let correlation_id = CorrelationId::new();
        let scope_digest = selection.scope.digest().map_err(|_| invalid("scan scope is invalid"))?;
        let scope_json = serde_json::to_string(&selection.scope)
            .map_err(|_| invalid("scan scope could not be encoded"))?;
        let project = selection.project_id.as_uuid().as_bytes().to_vec();
        let id = *uuid::Uuid::now_v7().as_bytes();
        let mut connection = self.store.lock().map_err(map_store)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| map_sql(error, correlation_id))?;
        let previous: Option<i64> = transaction
            .query_row(
                "SELECT MAX(selection_epoch) FROM catalog_owner_selections WHERE project_id = ?1 AND scope_digest = ?2",
                params![project, scope_digest.as_bytes().to_vec()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| map_sql(error, correlation_id))?
            .flatten();
        let epoch = previous.unwrap_or(0).checked_add(1).ok_or_else(|| invalid("epoch overflow"))?;
        transaction
            .execute(
                "UPDATE catalog_owner_selections SET current_for_scope = 0 WHERE project_id = ?1 AND scope_digest = ?2 AND current_for_scope = 1",
                params![project, scope_digest.as_bytes().to_vec()],
            )
            .map_err(|error| map_sql(error, correlation_id))?;
        transaction
            .execute(
                "INSERT INTO catalog_owner_selections (owner_selection_id, project_id, selection_epoch, current_for_scope, verified_pack_digest, scope_digest, scope_json, source_revision_id, pinned_source_digest, revoked) \
                 VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, 0)",
                params![
                    id.to_vec(),
                    project,
                    epoch,
                    selection.analyzer_digest.as_bytes().to_vec(),
                    scope_digest.as_bytes().to_vec(),
                    scope_json,
                    selection.source_revision_id.as_uuid().as_bytes().to_vec(),
                    selection.pinned_source_digest.as_bytes().to_vec(),
                ],
            )
            .map_err(|error| map_sql(error, correlation_id))?;
        transaction.commit().map_err(|error| map_sql(error, correlation_id))?;
        Ok(RecordedOwnerSelection {
            owner_selection_id: id,
            epoch: u64::try_from(epoch).map_err(|_| invalid("epoch overflow"))?,
        })
    }
}
