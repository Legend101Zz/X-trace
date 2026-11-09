//! Cumulative agent-capacity reports, kept independently of recording admission.

use rusqlite::{Connection, params};
use xtrace_domain::ids::Id as _;
use xtrace_domain::{CorrelationId, ProjectId, RecordingId, RuntimeSessionId};

use crate::{SqliteStore, StoreError, StoreErrorKind};

pub(crate) fn persist(
    store: &SqliteStore,
    project_id: ProjectId,
    session_id: RuntimeSessionId,
    count: u64,
) -> Result<(), StoreError> {
    let correlation = CorrelationId::new();
    let count = i64::try_from(count).map_err(|_| {
        StoreError::new(StoreErrorKind::Validation, "invalid session rejection count", correlation)
    })?;
    let connection = store.lock()?;
    connection
        .execute(
            "INSERT INTO session_health (project_id, runtime_session_id, rejected_requests)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (project_id, runtime_session_id) DO UPDATE SET
             rejected_requests = MAX(session_health.rejected_requests, excluded.rejected_requests)",
            params![project_id.as_uuid().as_bytes(), session_id.as_uuid().as_bytes(), count],
        )
        .map_err(|error| StoreError::from_rusqlite(error, correlation))?;
    Ok(())
}

/// Session reports have no position inside a recording. Keep them as contextual evidence,
/// never as synthetic events with invented sequence numbers, timing or request identities.
pub(crate) fn recording_context(
    connection: &Connection,
    recording_id: RecordingId,
) -> rusqlite::Result<xtrace_application::recording_queries::SessionContext> {
    let (session, count): (Vec<u8>, Option<i64>) = connection.query_row(
        "SELECT r.runtime_session_id, h.rejected_requests FROM recordings r
         LEFT JOIN session_health h ON h.project_id = r.project_id
             AND h.runtime_session_id = r.runtime_session_id
         WHERE r.recording_id = ?1",
        params![recording_id.as_uuid().as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let session = uuid::Uuid::from_slice(&session).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let rejected_requests = count
        .map(|count| u64::try_from(count).map(|count| count.to_string()))
        .transpose()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(xtrace_application::recording_queries::SessionContext {
        runtime_session_id: RuntimeSessionId::from_uuid(session),
        rejected_requests,
    })
}
